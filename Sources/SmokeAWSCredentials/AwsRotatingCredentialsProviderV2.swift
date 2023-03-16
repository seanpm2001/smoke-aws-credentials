// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// A copy of the License is located at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//
//  AwsRotatingCredentialsV2.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeHTTPClient
import SmokeAWSCore
import Logging

private let secondsToNanoSeconds: UInt64 = 1_000_000_000

/**
 A protocol that retrieves `ExpiringCredentials` and that is closable.
 */
public protocol ExpiringCredentialsRetrieverV2 {

    /**
     Gracefully shuts down this retriever. This function is idempotent and
     will handle being called multiple times. Will return when shutdown is complete.
     */
    func shutdown() async throws
    
    /**
     Retrieves a new instance of `ExpiringCredentials`.
     */
    func get() async throws -> ExpiringCredentials
}

/**
 Class that manages the rotating credentials.
 */
public struct AwsRotatingCredentialsProviderV2: StoppableCredentialsProviderV2 {
    public var status: Status {
        get async {
            return await self.state.status
        }
    }
    
    public var credentials: Credentials {
        return self.internalProvider.expiringCredentials
    }
    
    public enum Status {
        case initialized
        case running
        case shuttingDown
        case stopped
    }
    
    internal actor State {
        var status: Status = .initialized
        var awaitingContinuations: [CheckedContinuation<Void, Error>] = []
        
        func withStatus<Output>(_ handler: (Status) -> (update: (status: Status, resumeContinuations: Bool)?, output: Output)) -> Output {
            let (update, output) = handler(status)
            
            if let update {
                self.status = update.status
                
                if update.resumeContinuations {
                    self.awaitingContinuations.forEach { $0.resume(returning: ()) }
                    self.awaitingContinuations = []
                }
            }
            
            return output
        }
        
        func verifyWorkerNotCancelled() -> Bool {
            guard case .running = status else {
                status = .stopped
                self.awaitingContinuations.forEach { $0.resume(returning: ()) }
                self.awaitingContinuations = []
                return false
            }
            
            return true
        }
        
        func untilShutdown() async throws {
            return try await withCheckedThrowingContinuation { cont in
                if !addContinuationIfShutdown(newContinuation: cont) {
                    // continuation will be resumed when the server shuts down
                } else {
                    // server is already shutdown
                    cont.resume(returning: ())
                }
            }
        }
        
        func addContinuationIfShutdown(newContinuation: CheckedContinuation<Void, Error>) -> Bool {
            if case .stopped = status {
                return true
            }
            
            self.awaitingContinuations.append(newContinuation)
            
            return false
        }
    }
    
    private let internalProvider: AwsRotatingCredentialsInternalProvider
    private let state: State
    private let roleSessionName: String?
    private let logger: Logger
    
    /**
     Initializer that accepts the initial ExpiringCredentials instance for this provider.
     
     - Parameters:
        - expiringCredentialsRetriever: retriever of expiring credentials.
     */
    public init(expiringCredentialsRetriever: ExpiringCredentialsRetrieverV2,
                roleSessionName: String?,
                logger: Logger) async throws {
        let state = State()
        self.internalProvider = try await AwsRotatingCredentialsInternalProvider(expiringCredentialsRetriever: expiringCredentialsRetriever,
                                                                                 roleSessionName: roleSessionName, logger: logger) {
            return await state.verifyWorkerNotCancelled()
        }
        self.roleSessionName = roleSessionName
        self.logger = logger
        self.state = state
    }
    
    /**
     Schedules credentials rotation to begin.
     */
    public func start() async {
        return await self.state.withStatus { status -> (update: (Status, Bool)?, output: Void) in
            guard case .initialized = status else {
                // if this instance isn't in the initialized state, do nothing
                return (update: nil, output: ())
            }
            
            // only actually need to start updating credentials if the
            // initial ones expire
            if self.internalProvider.expiringCredentials.expiration != nil {
                Task(priority: .low) {
                    do {
                        try await self.internalProvider.run()
                    } catch {
                        let logEntryPrefix: String
                        if let roleSessionName = self.roleSessionName {
                            logEntryPrefix = "Credentials for session '\(roleSessionName)'"
                        } else {
                            logEntryPrefix = "Credentials"
                        }
                        
                        self.logger.error(
                            "\(logEntryPrefix) rotation stopped due to error \(error).")
                    }
                }
            }
            
            return (update: nil, output: ())
        }
    }
    
    /**
     Gracefully shuts down credentials rotation, letting any ongoing work complete..
     */
    public func shutdown() async throws {
        let doShutdown = await self.state.withStatus { status -> (update: (Status, Bool)?, output: Bool) in
            // if there is currently a worker to shutdown
            switch status {
            case .initialized:
                // no worker ever started, can just go straight to stopped
                return (update: (status: .stopped, resumeContinuations: true), output: true)
            case .running:
                return (update: (status: .shuttingDown, resumeContinuations: false), output: true)
            default:
                // nothing to do
                break
            }
            
            return (update: nil, output: false)
        }
        
        if doShutdown {
            try await self.internalProvider.shutdown()
        }
    }
    
    public func untilShutdown() async throws {
        return try await self.state.untilShutdown()
    }
}

internal class AwsRotatingCredentialsInternalProvider {
    public var expiringCredentials: ExpiringCredentials
    
    let expiringCredentialsRetriever: ExpiringCredentialsRetrieverV2
    let verifyWorkerNotCancelled: () async -> Bool
    let roleSessionName: String?
    let logger: Logger
    
    let expirationBufferSeconds = 300.0 // 5 minutes
    let validCredentialsRetrySeconds = 60.0 // 1 minute
    let invalidCredentialsRetrySeconds = 3600.0 // 1 hour
    
    /**
     Initializer that accepts the initial ExpiringCredentials instance for this provider.
     
     - Parameters:
        - expiringCredentialsRetriever: retriever of expiring credentials.
     */
    internal init(expiringCredentialsRetriever: ExpiringCredentialsRetrieverV2,
                  roleSessionName: String?,
                  logger: Logger,
                  verifyWorkerNotCancelled: @escaping () async -> Bool) async throws {
        self.expiringCredentials = try await expiringCredentialsRetriever.get()
        self.verifyWorkerNotCancelled = verifyWorkerNotCancelled
        self.expiringCredentialsRetriever = expiringCredentialsRetriever
        self.roleSessionName = roleSessionName
        self.logger = logger
    }
    
    func shutdown() async throws {
        try await self.expiringCredentialsRetriever.shutdown()
    }
    
    func run() async throws {
        var expiration: Date? = self.expiringCredentials.expiration
                
        while let currentExpiration = expiration {
            guard await self.verifyWorkerNotCancelled() else {
                return
            }
            
            // create a deadline 5 minutes before the expiration
            let timeInterval = (currentExpiration - expirationBufferSeconds).timeIntervalSinceNow
            let timeInternalInMinutes = timeInterval / 60
            
            let minutes: Int = Int(timeInternalInMinutes) % 60
            let hours: Int = Int(timeInternalInMinutes) / 60
                        
            let logEntryPrefix: String
            if let roleSessionName = self.roleSessionName {
                logEntryPrefix = "Credentials for session '\(roleSessionName)'"
            } else {
                logEntryPrefix = "Credentials"
            }
            
            self.logger.trace(
                "\(logEntryPrefix) updated; rotation scheduled in \(hours) hours, \(minutes) minutes.")
            try await Task.sleep(nanoseconds: UInt64(timeInterval) * secondsToNanoSeconds)
            
            expiration = await updateCredentials()
        }
    }
    
    private func updateCredentials() async
    -> Date? {
        let logEntryPrefix: String
        if let roleSessionName = self.roleSessionName {
            logEntryPrefix = "Credentials for session '\(roleSessionName)'"
        } else {
            logEntryPrefix = "Credentials"
        }
        
        self.logger.trace("\(logEntryPrefix) about to expire; rotating.")
        
        let expiration: Date?
        do {
            let expiringCredentials = try await self.expiringCredentialsRetriever.get()
            
            self.expiringCredentials = expiringCredentials
            
            expiration = expiringCredentials.expiration
        } catch {
            let timeIntervalSinceNow =
                self.expiringCredentials.expiration?.timeIntervalSinceNow ?? 0
            
            let retryDuration: Double
            let logPrefix = "\(logEntryPrefix) rotation failed."
            
            // if the expiry of the current credentials is still in the future
            if timeIntervalSinceNow > 0 {
                // try again relatively soon (still within the 5 minute credentials
                // expirary buffer) to get new credentials
                retryDuration = self.validCredentialsRetrySeconds
                
                self.logger.warning(
                    "\(logPrefix) Credentials still valid. Attempting credentials refresh in 1 minute.")
            } else {
                // at this point, we have tried multiple times to get new credentials
                // something is quite wrong; try again in the future but at
                // a reduced frequency
                retryDuration = self.invalidCredentialsRetrySeconds
                
                self.logger.error(
                    "\(logPrefix) Credentials no longer valid. Attempting credentials refresh in 1 hour.")
            }
            
            expiration = Date(timeIntervalSinceNow: retryDuration)
        }
        
        return expiration
    }
}
