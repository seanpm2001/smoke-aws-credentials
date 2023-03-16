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
//  AwsContainerRotatingCredentialsV2+get.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeAWSCore
import SmokeAWSHttp
import Logging
import SmokeHTTPClient
import AsyncHTTPClient
import NIOHTTP1

internal protocol ContainerExpiringCredentialsRetrieverProtocol: ExpiringCredentialsRetrieverV2 {
    init(eventLoopProvider: HTTPClient.EventLoopGroupProvider, credentialsPath: String, logger: Logger)
}

internal protocol DevExpiringCredentialsRetrieverProtocol: ExpiringCredentialsRetrieverV2 {
    init(iamRoleArn: String)
}

public typealias AwsContainerRotatingCredentialsProviderV2 = AwsRotatingCredentialsProviderV2

public extension AwsContainerRotatingCredentialsProviderV2 {
    /**
     The Environment variable that can be passed in conjunction with
     the DEBUG compiler flag to gain credentials based on the
     IAM Role ARN specified.
 
     If this Environment variable and the DEBUG compiler flag are specified,
     this class will first attempt to obtain credentials from the container
     environment and then static credentials under the AWS_SECRET_ACCESS_KEY
     and AWS_ACCESS_KEY_ID keys. If neither are present, this class will call
     the shell script-
       /usr/local/bin/get-credentials.sh -r <role> -d <role lifetype>
     
     This script should write to its standard output a JSON structure capable of
     being decoded into the ExpiringCredentials structure.
     */
    static let devIamRoleArnEnvironmentVariable = "DEV_CREDENTIALS_IAM_ROLE_ARN"
    
    /**
     Static function that retrieves credentials provider from the specified environment -
     either rotating credentials retrieved from an endpoint specified under the
     AWS_CONTAINER_CREDENTIALS_RELATIVE_URI key or if that key isn't present,
     static credentials under the AWS_SECRET_ACCESS_KEY and AWS_ACCESS_KEY_ID keys.
     */
    static func get(
        fromEnvironment environment: [String: String] = ProcessInfo.processInfo.environment,
        logger: Logging.Logger = Logger(label: "com.amazon.SmokeAWSCredentials"),
        eventLoopProvider: HTTPClient.EventLoopGroupProvider = .createNew) async
    -> StoppableCredentialsProviderV2? {
        return await get(fromEnvironment: environment,
                         containerRetrieverType: ContainerExpiringCredentialsRetriever.self,
                         devRetrieverType: DevExpiringCredentialsRetriever.self,
                         logger: logger, eventLoopProvider: eventLoopProvider)
    }
    
    /**
     Internal entry point for testing
     */
    internal static func get<ContainerRetrieverType: ContainerExpiringCredentialsRetrieverProtocol,
                             DevRetrieverType: DevExpiringCredentialsRetrieverProtocol>(
            fromEnvironment environment: [String: String],
            containerRetrieverType: ContainerRetrieverType.Type, devRetrieverType: DevRetrieverType.Type,
            logger originalLogger: Logging.Logger = Logger(label: "com.amazon.SmokeAWSCredentials"),
            eventLoopProvider: HTTPClient.EventLoopGroupProvider = .createNew) async
        -> StoppableCredentialsProviderV2? {
            var logger = originalLogger
            logger[metadataKey: "credentials.source"] = "environment"
            
            if let rotatingCredentials = await getContainerRotatingCredentialsProvider(fromEnvironment: environment,
                                                                                       retrieverType: containerRetrieverType,
                                                                                       eventLoopProvider: eventLoopProvider,
                                                                                       logger: logger) {
                return rotatingCredentials
            }
            
            if let staticCredentials = getStaticCredentialsProvider(fromEnvironment: environment, logger: logger) {
                return staticCredentials
            }
            
            #if DEBUG
            if let rotatingCredentials = await getDevRotatingCredentialsProvider(fromEnvironment: environment,
                                                                                 retrieverType: devRetrieverType,
                                                                                 logger: logger) {
                return rotatingCredentials
            }
            #endif
            
            return nil
    }
    
    private static func getStaticCredentialsProvider(
        fromEnvironment environment: [String: String],
        logger: Logger)
        -> StoppableCredentialsProviderV2? {
            // get the values of the environment variables
            let awsAccessKeyId = environment["AWS_ACCESS_KEY_ID"]
            let awsSecretAccessKey = environment["AWS_SECRET_ACCESS_KEY"]
            let sessionToken = environment["AWS_SESSION_TOKEN"]
            
            guard let secretAccessKey = awsSecretAccessKey, let accessKeyId = awsAccessKeyId else {
                let logMessage = "'AWS_ACCESS_KEY_ID' and 'AWS_SESSION_TOKEN' environment variables not"
                    + "specified. Static credentials not available."
                logger.trace("\(logMessage)")
                
                return nil
            }
            
            logger.trace("Static credentials retrieved from environment.")
            
            // return these credentials
            return SmokeAWSCore.StaticCredentials(accessKeyId: accessKeyId,
                                                  secretAccessKey: secretAccessKey,
                                                  sessionToken: sessionToken)
    }
    
#if DEBUG
    private static func getDevRotatingCredentialsProvider<RetrieverType: DevExpiringCredentialsRetrieverProtocol>(
            fromEnvironment environment: [String: String],
            retrieverType: RetrieverType.Type,
            logger: Logger) async
    -> StoppableCredentialsProviderV2? {
        // get the values of the environment variables
        let devCredentialsIamRoleArn = environment["DEV_CREDENTIALS_IAM_ROLE_ARN"]
        
        guard let iamRoleArn = devCredentialsIamRoleArn else {
            let logMessage = "'DEV_CREDENTIALS_IAM_ROLE_ARN' environment variable not specified."
                + " Dev rotating credentials not available."
            
            logger.trace("\(logMessage)")
            
            return nil
        }
        
        let credentialsRetriever = RetrieverType(iamRoleArn: iamRoleArn)
        
        do {
            let awsContainerRotatingCredentialsProvider =
                try await AwsContainerRotatingCredentialsProviderV2(
                        expiringCredentialsRetriever: credentialsRetriever,
                        roleSessionName: nil,
                        logger: logger)
            
            await awsContainerRotatingCredentialsProvider.start()
            
            logger.trace("Rotating credentials retrieved from environment.")
            
            // return the credentials
            return awsContainerRotatingCredentialsProvider
        } catch {
            logger.error("Retrieving rotating credentials rotation failed: '\(error)'")
            
            return nil
        }
    }
#endif
    
    private static func getContainerRotatingCredentialsProvider<RetrieverType: ContainerExpiringCredentialsRetrieverProtocol>(
        fromEnvironment environment: [String: String],
        retrieverType: RetrieverType.Type,
        eventLoopProvider: HTTPClient.EventLoopGroupProvider,
        logger: Logger) async
    -> StoppableCredentialsProviderV2? {
        // get the values of the environment variables
        let awsContainerCredentialsRelativeUri = environment["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
        
        guard let credentialsPath = awsContainerCredentialsRelativeUri else {
            let logMessage = "'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' environment variable not specified."
                + " Rotating credentials not available."
            
            logger.trace("\(logMessage)")
            
            return nil
        }
        
        let credentialsRetriever = RetrieverType(eventLoopProvider: eventLoopProvider, credentialsPath: credentialsPath,
                                                 logger: logger)
            
        do {
            let awsContainerRotatingCredentialsProvider =
                try await AwsContainerRotatingCredentialsProviderV2(
                        expiringCredentialsRetriever: credentialsRetriever,
                        roleSessionName: nil,
                        logger: logger)
            
            await awsContainerRotatingCredentialsProvider.start()
            
            logger.trace("Rotating credentials retrieved from environment.")
            
            // return the credentials
            return awsContainerRotatingCredentialsProvider
        } catch {
            logger.error("Retrieving rotating credentials rotation failed: '\(error)'")
            
            return nil
        }
    }
    
    internal struct DevExpiringCredentialsRetriever: DevExpiringCredentialsRetrieverProtocol {
        let iamRoleArn: String
        
        func shutdown() async throws {
            // nothing to do
        }
        
        func get() async throws -> ExpiringCredentials {
            let outputPipe = Pipe()
            
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            task.arguments = ["/usr/local/bin/get-credentials.sh",
                              "-r",
                              self.iamRoleArn,
                              "-d",
                              "900"]
            task.standardOutput = outputPipe
            try task.run()
            task.waitUntilExit()

            let bodyData = outputPipe.fileHandleForReading.availableData
            
            return try ExpiringCredentials.getCurrentCredentials(data: bodyData)
        }
    }
    
    internal struct ContainerExpiringCredentialsRetriever: ContainerExpiringCredentialsRetrieverProtocol {
        let httpClient: HTTPClient
        let credentialsPath: String
        let logger: Logger
        
        init(eventLoopProvider: HTTPClient.EventLoopGroupProvider, credentialsPath: String, logger: Logger) {
            self.httpClient = HTTPClient(eventLoopGroupProvider: eventLoopProvider)
            self.credentialsPath = credentialsPath
            self.logger = logger
        }
        
        // the endpoint for obtaining credentials from the ECS container
        // https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
        private static let credentialsHost = "169.254.170.2"
        private static let credentialsPort = 80
        
        func shutdown() async throws {
            try await self.httpClient.shutdown()
        }
        
        func get() async throws -> ExpiringCredentials {
            let infix: String
            if let credentialsPrefix = self.credentialsPath.first, credentialsPrefix != "/" {
                infix = "/"
            } else {
                infix = ""
            }
            
            let endpoint = "http://\(Self.credentialsHost)\(infix)\(self.credentialsPath)"
            
            let headers = [("User-Agent", "SmokeAWSCredentials"),
                ("Content-Length", "0"),
                ("Host", Self.credentialsHost),
                ("Accept", "*/*")]
            
            self.logger.trace("Retrieving environment credentials from endpoint: \(endpoint)")
            
            let request = try HTTPClient.Request(url: endpoint, method: .GET, headers: HTTPHeaders(headers))
            
            let response = try await self.httpClient.execute(request: request).get()
            
            // if the response status is ok
            guard case .ok = response.status else {
                let bodyAsString: String?
                if var body = response.body {
                    let byteBufferSize = body.readableBytes
                    let data = body.readData(length: byteBufferSize) ?? Data()
                    
                    bodyAsString = String(data: data, encoding: .utf8)
                } else {
                    bodyAsString = nil
                }
                
                throw CredentialsHTTPError.errorResponse(response.status.code, bodyAsString)
            }
                
            let bodyData: Data
            if var body = response.body {
                let byteBufferSize = body.readableBytes
                bodyData = body.readData(length: byteBufferSize) ?? Data()
            } else {
                bodyData = Data()
            }
                
            return try ExpiringCredentials.getCurrentCredentials(data: bodyData)
        }
    }
}
