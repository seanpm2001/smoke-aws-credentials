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
//  StoppableCredentialsProviderV2.swift
//  SmokeAWSCredentials
//

import Foundation
import SmokeAWSCore

/**
 Extension protocol of the CredentialsProvider protocol that adds
 functions to stop and wait on background management of these
 credentials.
 */
public protocol StoppableCredentialsProviderV2: CredentialsProvider {
    /**
     Gracefully shuts down background management of these
     credentials. May block until ongoing work completes.
     */
    func shutdown() async throws
}

/**
 Conform StaticCredentials to StoppableCredentialsProvider to allow
 StaticCredentials to be returned. Nothing actually needs to be stopped.
 */
extension SmokeAWSCore.StaticCredentials: StoppableCredentialsProviderV2 {

}
