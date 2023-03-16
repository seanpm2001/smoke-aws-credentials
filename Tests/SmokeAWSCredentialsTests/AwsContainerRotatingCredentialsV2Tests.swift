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
//  AwsContainerRotatingCredentialsV2Tests.swift
//  SmokeAWSCredentials
//

import XCTest
@testable import SmokeAWSCredentials
import SmokeHTTPClient
import AsyncHTTPClient
import Logging

internal struct TestExpiringCredentialsRetriever: DevExpiringCredentialsRetrieverProtocol, ContainerExpiringCredentialsRetrieverProtocol {
    init(iamRoleArn: String) {
        // nothing to do
    }
    
    init(eventLoopProvider: AsyncHTTPClient.HTTPClient.EventLoopGroupProvider, credentialsPath: String, logger: Logger) {
        XCTAssertEqual(credentialsPath, "endpoint")
    }
    
    
    func shutdown() async throws {
        // nothing to do
    }
    
    func get() async throws -> ExpiringCredentials {
        // don't provide an expiration to avoid setting up a rotation timer in the test
        return ExpiringCredentials(accessKeyId: TestVariables.accessKeyId,
                                   expiration: nil,
                                   secretAccessKey: TestVariables.secretAccessKey,
                                   sessionToken: TestVariables.sessionToken)
    }
}

class AwsContainerRotatingCredentialsV2Tests: XCTestCase {    
    func testGetAwsContainerCredentials() async throws {
        let environment = ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "endpoint"]
        let credentialsProvider = await AwsContainerRotatingCredentialsProviderV2.get(fromEnvironment: environment,
                                                                                      containerRetrieverType: TestExpiringCredentialsRetriever.self,
                                                                                      devRetrieverType: TestExpiringCredentialsRetriever.self)!
        let credentials = credentialsProvider.credentials
        
        XCTAssertEqual(TestVariables.accessKeyId, credentials.accessKeyId)
        XCTAssertEqual(TestVariables.secretAccessKey, credentials.secretAccessKey)
        XCTAssertEqual(TestVariables.sessionToken, credentials.sessionToken)
        
        try await credentialsProvider.shutdown()
    }
    
    func testStaticCredentials() async throws {
        let environment = ["AWS_ACCESS_KEY_ID": TestVariables.accessKeyId2,
                           "AWS_SECRET_ACCESS_KEY": TestVariables.secretAccessKey2,
                           "AWS_SESSION_TOKEN": TestVariables.sessionToken2]
        let credentialsProvider = await AwsContainerRotatingCredentialsProviderV2.get(fromEnvironment: environment,
                                                                                      containerRetrieverType: TestExpiringCredentialsRetriever.self,
                                                                                      devRetrieverType: TestExpiringCredentialsRetriever.self)!
        let credentials = credentialsProvider.credentials
        
        XCTAssertEqual(TestVariables.accessKeyId2, credentials.accessKeyId)
        XCTAssertEqual(TestVariables.secretAccessKey2, credentials.secretAccessKey)
        XCTAssertEqual(TestVariables.sessionToken2, credentials.sessionToken)
        
        try await credentialsProvider.shutdown()
    }
 
    func testNoCredentials() async throws {
        let credentialsProvider = await AwsContainerRotatingCredentialsProviderV2.get(fromEnvironment: [:],
                                                                                      containerRetrieverType: TestExpiringCredentialsRetriever.self,
                                                                                      devRetrieverType: TestExpiringCredentialsRetriever.self)
        
        XCTAssertNil(credentialsProvider)
        
        try await credentialsProvider?.shutdown()
    }
}

