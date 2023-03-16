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
//  SecurityTokenClientProtocol+getAssumedCredentialsAsync.swift
//  SmokeAWSCredentials
//

import Foundation
import SecurityTokenClient
import SecurityTokenModel
import SmokeAWSCore
import SmokeHTTPClient
import AsyncHTTPClient
import Logging

internal struct AWSSTSExpiringCredentialsRetrieverV2<InvocationReportingType: HTTPClientCoreInvocationReporting>: ExpiringCredentialsRetrieverV2 {
    let client: AWSSecurityTokenClient<InvocationReportingType>
    let roleArn: String
    let roleSessionName: String
    let durationSeconds: Int?
    
    init(credentialsProvider: CredentialsProvider,
         roleArn: String,
         roleSessionName: String,
         durationSeconds: Int?,
         retryConfiguration: HTTPClientRetryConfiguration,
         eventLoopProvider: HTTPClient.EventLoopGroupProvider,
         reporting: InvocationReportingType) {
        self.client = AWSSecurityTokenClient(
            credentialsProvider: credentialsProvider,
            reporting: reporting,
            retryConfiguration: retryConfiguration,
            eventLoopProvider: eventLoopProvider)
        self.roleArn = roleArn
        self.roleSessionName = roleSessionName
        self.durationSeconds = durationSeconds
    }
    
    func shutdown() async throws {
        try await self.client.shutdown()
    }
    
    func get() throws -> ExpiringCredentials {
        return try client.getAssumedExpiringCredentials(
                    roleArn: roleArn,
                    roleSessionName: roleSessionName,
                    durationSeconds: durationSeconds)
    }
}

extension SecurityTokenClientProtocol {
    /**
     Gets assumed role credentials from the SecurityTokenService. Returns nil
     if no assumed credentials could be obtained.
    
     - Parameters:
        - roleArn: the ARN of the role that is to be assumed.ARN
        - roleSessionName: the session name to use when assuming the role.
        - durationSeconds: The duration, in seconds, of the role session. The value can
            range from 900 seconds (15 minutes) to 3600 seconds (1 hour). By default, the value
            is set to 3600 seconds.
     */
    internal func getAssumedExpiringCredentialsV2(roleArn: String,
                                                  roleSessionName: String,
                                                  durationSeconds: Int?) async throws -> ExpiringCredentials {
        let input = SecurityTokenModel.AssumeRoleRequest(durationSeconds: durationSeconds,
                                                         roleArn: roleArn,
                                                         roleSessionName: roleSessionName)
        
        let output: SecurityTokenModel.AssumeRoleResponseForAssumeRole
        do {
            // call to assume the role
            output = try await assumeRole(input: input)
        } catch {
            throw AssumingRoleError.unableToAssumeRole(arn: roleArn, error: error)
        }
        
        guard let stsCredentials = output.assumeRoleResult.credentials else {
            throw AssumingRoleError.noCredentialsReturned(arn: roleArn)
        }
    
        return ExpiringCredentials(accessKeyId: stsCredentials.accessKeyId,
                                   expiration: stsCredentials.expiration.dateFromISO8601String ?? nil,
                                   secretAccessKey: stsCredentials.secretAccessKey,
                                   sessionToken: stsCredentials.sessionToken)
    }
    
    /**
     Function that retrieves StaticCredentials from the provided token service.
     */
    internal static func getAssumedStaticCredentialsV2<InvocationReportingType: HTTPClientCoreInvocationReporting>(
        roleArn: String,
        roleSessionName: String,
        credentialsProvider: CredentialsProvider,
        reporting: InvocationReportingType,
        retryConfiguration: HTTPClientRetryConfiguration) async
    -> StaticCredentials? {
        let securityTokenClient = AWSSecurityTokenClient(
            credentialsProvider: credentialsProvider,
            reporting: reporting,
            retryConfiguration: retryConfiguration)
        let staticCredentials: StaticCredentials?
        do {
            let delegatedCredentials = try await securityTokenClient.getAssumedExpiringCredentialsV2(
                roleArn: roleArn,
                roleSessionName: roleSessionName,
                durationSeconds: nil)
            
            staticCredentials = StaticCredentials(accessKeyId: delegatedCredentials.accessKeyId,
                                                  secretAccessKey: delegatedCredentials.secretAccessKey,
                                                  sessionToken: delegatedCredentials.sessionToken)
        } catch {
            reporting.logger.warning("Unable to assumed delegated rotating credentials: \(error).")
    
            staticCredentials = nil
        }
            
        do {
            try await securityTokenClient.shutdown()
        } catch {
            reporting.logger.warning("Failed to close AWSSecurityTokenClient due to error: \(error).")
        }
        
        return staticCredentials
    }
    
    /**
     Function that retrieves AssumedRotatingCredentials from the provided token service.
     */
    internal static func getAssumedRotatingCredentialsV2<InvocationReportingType: HTTPClientCoreInvocationReporting>(
        roleArn: String,
        roleSessionName: String,
        credentialsProvider: CredentialsProvider,
        durationSeconds: Int?,
        reporting: InvocationReportingType,
        retryConfiguration: HTTPClientRetryConfiguration,
        eventLoopProvider: HTTPClient.EventLoopGroupProvider) async -> StoppableCredentialsProviderV2? {
        let credentialsRetriever = AWSSTSExpiringCredentialsRetrieverV2(
            credentialsProvider: credentialsProvider,
            roleArn: roleArn,
            roleSessionName: roleSessionName,
            durationSeconds: durationSeconds,
            retryConfiguration: retryConfiguration,
            eventLoopProvider: eventLoopProvider,
            reporting: reporting)
        
        let delegatedRotatingCredentials: AwsRotatingCredentialsProviderV2
        do {
            delegatedRotatingCredentials = try await AwsRotatingCredentialsProviderV2(
                expiringCredentialsRetriever: credentialsRetriever,
                roleSessionName: roleSessionName,
                logger: reporting.logger)
        } catch {
            reporting.logger.warning("Unable to assumed delegated rotating credentials: \(error).")
    
            return nil
        }
    
        await delegatedRotatingCredentials.start()
    
        return delegatedRotatingCredentials
    }
}
