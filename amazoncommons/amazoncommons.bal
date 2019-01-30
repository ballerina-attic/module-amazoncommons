// Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/time;
import ballerina/crypto;
import ballerina/encoding;

final string DATE_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
final string SHORT_DATE_FORMAT = "yyyyMMdd";
final string AWS_SIGN_ALGORITHM = "AWS4-HMAC-SHA256";
public final string AMAZON_HOST = "amazonaws.com";
public final string DEFAULT_REGION = "us-east-1";

# Generates the Amzdate value given a specific time.
#
# + return - The Amzdate value
public function generateAmzdate(time:Time time) returns string {
    return time:format(time, DATE_FORMAT);
}

# Generates the Datestamp value given a specific time.
#
# + return - The Datestamp value
public function generateDatestamp(time:Time time) returns string {
    return time:format(time, SHORT_DATE_FORMAT);
}

# Populate the given headers map with the authorization header. All other headers must be passed into the
# `orderedHeaders` map in a manner where the keys are ordered; e.g. "X-Amz-Date" must be passed in.
# + accessKey - The access key
# + secretKey - The secret key
# + region - The AWS region, e.g. "us-west-1"
# + serviceName - The service to be used, e.g. "rekognition"
# + payload - The payload in text format
# + canonicalURI - Canonical URI, use "" if nothing
# + canonicalQueryString - CanonicalQuery String, use "" if nothing
# + orderedHeaders - The headers to be used in a key ordered manner
# + method - The HTTP method to be used in API calls
# + amzdate - The Amzdate
# + datestamp - The Datestamp
public function populateAuthorizationHeaders(string accessKey, string secretKey, string region, string serviceName,
                                             string payload, string canonicalURI, string canonicalQueryString,
                                             map<string> orderedHeaders, string method, string amzdate, 
                                             string datestamp) {
    string canonicalHeaders = "";
    string signedHeaders = "";   
    foreach var (k,v) in orderedHeaders {
        string cnheader = k.toLower();
        canonicalHeaders = canonicalHeaders + cnheader + ":" + v + "\n";
        signedHeaders = signedHeaders + cnheader + ";";
    }    
    if (signedHeaders.length() > 0) {
        // remove the extra ";" at the end
        signedHeaders = signedHeaders.substring(0, signedHeaders.length() - 1);
    }
    string payloadHash = encoding:encodeHex(crypto:hashSha256(payload.toByteArray("UTF-8"))).toLower();
    string canonicalRequest = method + "\n" + canonicalURI + "\n" + canonicalQueryString + "\n" + canonicalHeaders +
                              "\n" + signedHeaders + "\n" + payloadHash;
    string credentialScope = datestamp + "/" + region + "/" + serviceName + "/" + "aws4_request";
    string stringToSign = AWS_SIGN_ALGORITHM + "\n" + amzdate + "\n" + credentialScope + "\n" + 
                          encoding:encodeHex(crypto:hashSha256(canonicalRequest.toByteArray("UTF-8"))).toLower();
    byte[] signingKey = getSignatureKey(secretKey, datestamp, region, serviceName);
    string signature = encoding:encodeHex(crypto:hmacSha256(stringToSign.toByteArray("UTF-8"), signingKey)).toLower();
    string authorizationHeader = AWS_SIGN_ALGORITHM + " " + "Credential=" + accessKey + "/" + credentialScope + ", " + 
                                 "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;

    orderedHeaders["Authorization"] = authorizationHeader;
}

function sign(byte[] key, string msg) returns byte[] {
    return crypto:hmacSha256(msg.toByteArray("UTF-8"), key);
}

# Generates and returns the AWS signature key
# + secretKey - the secret key in string format as given in the AWS management console
# + datestamp - The Datestamp value
# + region - The AWS region, e.g. "us-west-1"
# + serviceName - The service to be used, e.g. "rekognition"
# + return - The signature
public function getSignatureKey(string secretKey, string datestamp, string region, string serviceName) returns byte[] {
    string awskey = ("AWS4" + secretKey);
    byte[] kDate = sign(awskey.toByteArray("UTF-8"), datestamp);
    byte[] kRegion = sign(kDate, region);
    byte[] kService = sign(kRegion, serviceName);
    byte[] kSigning = sign(kService, "aws4_request");
    return kSigning;
}

public type S3Object record {
    string bucket;
    string name;
    string objVersion = "";
};

