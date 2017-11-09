/*
Copyright TokenID 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// PBM ChainCode  Chaincode implementation
type passportChainCode struct {
}

type passport struct {
	ProviderEnrollmentID     string `json:"providerEnrollmentID"`     //Mundane passport ID - passport Provider given
	passportCode             string `json:"passportCode"`             //Issuer given passport ID
	passportTypeCode         string `json:"passportTypeCode"`         //Virtual passport Type Code (Issuer defined) - gotten from TCert
	IssuerID                 string `json:"issuerID"`                 //Virtual passport IssuerID - gotten from TCert
	IssuerCode               string `json:"issuerCode"`               //Virtual passport Issuer Code - gotten from TCert
	IssuerBorderManagement   string `json:"issuerBorderManagement"`       //Virtual passport Issuer Border Management - gotten from TCert or Ecert
	EncryptedPayload         string `json:"encryptedPayload"`         // Encrypted Virtual passport (EVI) payload
	EncryptedKey             string `json:"encryptedKey"`             //Symmetric encryption key for EVI payload encrypted with the public key
	MetaData                 string `json:"metaData"`                 //Miscellanous passport Information - ONLY NON-SENSITIVE passport INFORMATION/ATTRIBUTES SHOULD BE ADDED
	EncryptedAttachmentURI   string `json:"encryptedAttachmentURI"`   //Encrypted URIs to Virtual passport Document e.g. Scanned document image
	CreatedBy                string `json:"createdBy"`                //passport Creator
	CreatedOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`     //Created on Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.
	LastUpdatedBy            string `json:"lastUpdatedBy"`            //Last Updated By
	LastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"` //Last Updated On Timestamp -   which is currently taken from the peer receiving the transaction. Note that this timestamp may not be the same with the other peers' time.
	IssuerVerified           bool   `json:"issuerVerified"`           //passport verified by Issuer
}

type passportMin struct {
	ProviderEnrollmentID     string `json:"providerEnrollmentID"`
	passportCode             string `json:"passportCode"`
	passportTypeCode         string `json:"passportTypeCode"`
	IssuerCode               string `json:"issuerCode"`
	IssuerID                 string `json:"issuerID"`
	IssuerBorderManagement   string `json:"issuerBorderManagement"`
	CreatedBy                string `json:"createdBy"`
	CreatedOnTxTimestamp     int64  `json:"createdOnTxTimestamp"`
	LastUpdatedBy            string `json:"lastUpdatedBy"`
	LastUpdatedOnTxTimestamp int64  `json:"lastUpdatedOnTxTimestamp"`
	IssuerVerified           bool   `json:"issuerVerified"`
}

//States key prefixes
const PUBLIC_KEY_PREFIX = "_PK"
const passport_TBL_PREFIX = "_TABLE"
const ISSUER_TBL_NAME = "ISSUERS_TABLE"

//"EVENTS"
const EVENT_NEW_passport_ENROLLED = "EVENT_NEW_passport_ENROLLED"
const EVENT_NEW_passport_ISSUED = "EVENT_NEW_passport_ISSUED"
const EVENT_NEW_ISSUER_ENROLLED = "EVENT_NEW_ISSUER_ENROLLED"

//ROLES
const ROLE_ISSUER = "Issuer"
const ROLE_PROVIDER = "Provider"
const ROLE_USER = "User"

var logger = shim.NewLogger("passportChaincode")

// ============================================================================================================================
// Main
// ============================================================================================================================
func main() {
	err := shim.Start(new(passportChainCode))
	if err != nil {
		fmt.Printf("Error starting passport ChainCode: %s", err)
	}
}

//=================================================================================================================================
//	 Ping Function
//=================================================================================================================================
//	 Pings the peer to keep the connection alive
//=================================================================================================================================
func (t *passportChainCode) Ping(stub shim.ChaincodeStubInterface) ([]byte, error) {
	return []byte("Hi, I'm up!"), nil
}

//=================================================================================================================================
//Initializes chaincode when deployed
//=================================================================================================================================
func (t *passportChainCode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2 -> [providerEnrollmentID, passportPublicKey]")
	}
	//Create initial passport table
	fmt.Println("Initializing passport for ->" + args[0])
	val, err := t.Initpassport(stub, args, true)
	if err != nil {
		fmt.Println(err)
	}
	return val, err
}

//=================================================================================================================================
//Initializes the passport and sets the default states
//=================================================================================================================================
func (t *passportChainCode) Initpassport(stub shim.ChaincodeStubInterface, args []string, isDeploymentCall bool) ([]byte, error) {

	if len(args) < 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2 -> [providerEnrollmentID , passportPublicKey]")
	}

	//Check if user is provider
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}
	isProv := isProvider(callerDetails)
	if isProv == false && isDeploymentCall == false { //If its a deployment call, TCert info will not be transmitted to other peers and the role won't be known
		return nil, errors.New("Access Denied")
	}

	var providerEnrollmentID, passportPublicKey string
	providerEnrollmentID = args[0]
	passportPublicKey = args[1]

	//Verify that Enrollment ID and Pubic key is not null
	if providerEnrollmentID == "" || passportPublicKey == "" {
		return nil, errors.New("Provider Enrollment ID or Public key cannot be null")
	}

	//Add Public key state
	existingPKBytes, err := stub.GetState(providerEnrollmentID + PUBLIC_KEY_PREFIX)

	if err == nil && existingPKBytes != nil {
		return nil, fmt.Errorf("Public Key for " + providerEnrollmentID + " already exists ")
	}
	fmt.Println(passportPublicKey)

	pkBytes := []byte(passportPublicKey)

	//Validate Public key is PEM format
	err = validatePublicKey(pkBytes)

	if err != nil {
		return nil, fmt.Errorf("Bad Public Key -> Public key must be in PEM format - [%v]", err)
	}

	//Set Public key state
	err = stub.PutState(providerEnrollmentID+PUBLIC_KEY_PREFIX, pkBytes)

	if err != nil {
		return nil, fmt.Errorf("Failed inserting public key, [%v] -> "+providerEnrollmentID, err)
	}

	//Create passport Table
	err = t.createpassportTable(stub, providerEnrollmentID)
	if err != nil {
		return nil, fmt.Errorf("Failed creating passport Table, [%v] -> "+providerEnrollmentID, err)
	}

	//Broadcast 'New Enrollment'  Event with enrollment ID
	err = stub.SetEvent(EVENT_NEW_passport_ENROLLED, []byte(providerEnrollmentID))

	if err != nil {
		return nil, fmt.Errorf("Failed to broadcast enrollment event, [%v] -> "+providerEnrollmentID, err)
	}

	return []byte("Enrollment Successful"), nil
}

//=================================================================================================================================
//	 Entry point to invoke a chaincode function
//=================================================================================================================================
func (t *passportChainCode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("invoke is running " + function)

	var bytes []byte
	var err error

	fmt.Println("function -> " + function)

	// Handle different functions
	if function == "init" { //initialize the chaincode state, used as reset
		bytes, err = t.Init(stub, "init", args)
	} else if function == "addpassport" {
		bytes, err = t.Addpassport(stub, args)
	} else if function == "removepassport" {
		bytes, err = t.Removepassport(stub, args)
	} else {
		fmt.Println("invoke did not find func: " + function) //error

		return nil, errors.New("Received unknown function invocation: " + function)
	}
	if err != nil {
		fmt.Println(err)
	}
	return bytes, err

}

//=================================================================================================================================
//	 Query is our entry point for queries
//=================================================================================================================================
func (t *passportChainCode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	fmt.Println("query is running " + function)

	// Handle different functions

	var bytes []byte
	var err error

	fmt.Println("function -> " + function)
	if function == "ping" {
		bytes, err = t.Ping(stub)

	} else if function == "getPassports" {
		bytes, err = t.GetPassports(stub, args)

	} else if function == "getpassport" {
		bytes, err = t.Getpassport(stub, args)
	} else if function == "getPublicKey" {
		bytes, err = t.GetPublicKey(stub, args)
	} else {
		fmt.Println("query did not find func: " + function) //error
		return nil, errors.New("Received unknown function query: " + function)
	}
	if err != nil {
		fmt.Println(err)
	}
	return bytes, err

}

//=================================================================================================================================
//	 Create passport table
//=================================================================================================================================

//Create passport Table
func (t *passportChainCode) createpassportTable(stub shim.ChaincodeStubInterface, enrollmentID string) error {

	var tableName string

	tableName = enrollmentID + passport_TBL_PREFIX

	// Create passport table
	tableErr := stub.CreateTable(tableName, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "ProviderEnrollmentID", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "passportCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "passportTypeCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "EncryptedPayload", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "IssuerCode", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IssuerID", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "IssuerBorderManagement", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "EncryptedKey", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "Metadata", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "IssuerVerified", Type: shim.ColumnDefinition_BOOL, Key: false},
		&shim.ColumnDefinition{Name: "EncryptedAttachmentURI", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "CreatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "CreatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
		&shim.ColumnDefinition{Name: "LastUpdatedBy", Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: "lastUpdatedOnTxTimeStamp", Type: shim.ColumnDefinition_INT64, Key: false},
	})
	if tableErr != nil {
		return fmt.Errorf("Failed creating passportTable table, [%v] -> "+enrollmentID, tableErr)
	}
	return nil
}

//=================================================================================================================================
//	 Add New Issued passport
//=================================================================================================================================
func (t *passportChainCode) Addpassport(stub shim.ChaincodeStubInterface, passportParams []string) ([]byte, error) {

	//Get Caller Details
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	//Check if Tcert has a valid role
	validRoles := hasValidRoles(callerDetails)

	if validRoles == false {
		return nil, fmt.Errorf("Access denied. Unknown role in Tcert -> " + callerDetails.role)
	}

	if len(passportParams) < 10 {
		return nil, errors.New("Incomplete number of arguments. Expected 10 -> [ProviderEnrollmentID, passportCode, passportTypeCode, EncryptedpassportPayload, EncryptionKey, IssuerID,  MetaData, EncryptedAttachmentURI, IssuerCode, IssuerBorderManagement ]")
	}

	if strings.EqualFold(callerDetails.role, ROLE_ISSUER) == false && strings.EqualFold(callerDetails.role, ROLE_PROVIDER) == false {
		return nil, errors.New("Access Denied. Not a provider or Issuer")
	}
	isProvider := isProvider(callerDetails)

	var issuerCode, issuerBorderManagement, issuerID string

	issuerVerified := false

	//For providers, issuer details are required to be submitted
	//Parameters should be in the order -> [ProviderEnrollmentID, passportCode, passportTypeCode, EncryptedpassportPayload, EncryptionKey, IssuerID,  MetaData, EncryptedAttachmentURI, IssuerCode, IssuerBorderManagement ]
	if isProvider == true {
		//Check for empty mandatory fields (first 5 fields)
		for i := 0; i < 6; i++ {
			if passportParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 5 which are ProviderEnrollmentID, passportCode, passportTypeCode, passportPayload and IssuerID")
			}
		}
		issuerID = passportParams[5]
		issuerCode = passportParams[8]
		issuerBorderManagement = passportParams[9]
		
	} else {
		//Issuer details are gotten from Transaction Certificate
		//Check for empty mandatory fields
		for i := 0; i < 5; i++ {
			if passportParams[i] == "" {
				return nil, errors.New("One or more mandatory fields is empty. Mandatory fields are the first 4 which are ProviderEnrollmentID, passportCode, passportTypeCode  and passportPayload")
			}
		}
		issuerID = callerDetails.issuerID
		issuerCode = callerDetails.issuerCode
		issuerBorderManagement = callerDetails.BorderManagement
		//Verified, since the passport is created by the issuer
		issuerVerified = true
	}

	if isProvider == false && (issuerCode == "" || issuerID == "" || issuerBorderManagement == "") {
		return nil, errors.New("One of the required fields are not available in transaction certificate [issuerCode, issuerID, BorderManagement] -> [" + issuerID + ", " + issuerID + "," + issuerBorderManagement + "]")
	}

	//Validate passport Type code
	passportTypeCode := passportParams[2]
	isValid, err := validatepassportTypeCode(passportTypeCode)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Could not validate passportTypeCode -> [%v]", err)
	}
	if isValid == false {
		return nil, fmt.Errorf("Invalid passportTypeCode. Must contain only AlphaNumeric characters, minimum length of 4 and maximum of 10")
	}

	providerEnrollmentID := passportParams[0]
	passportCode := passportParams[1]

	//Encrypted Payload
	encryptedPayload, err := decodeBase64(passportParams[3])
	if err != nil {
		return nil, fmt.Errorf("Bad Encrypted Payload [%v] ", err)
	}

	//Encrypted Key
	encryptedKey, err := decodeBase64(passportParams[4])
	if err != nil {
		return nil, fmt.Errorf("Bad Encrypted Key [%v] ", err)
	}

	//Encrypted Attachment
	encryptedAttachmentURIString := passportParams[7]
	var encryptedAttachmentURI []byte
	if encryptedAttachmentURIString != "" {
		encryptedAttachmentURI, err = decodeBase64(passportParams[7])
		if err != nil {
			return nil, fmt.Errorf("Bad Encrypted AttachmentURI [%v] ", err)
		}

	}

	//Check if similar passport exists
	var key2columns []shim.Column
	key2Col1 := shim.Column{Value: &shim.Column_String_{String_: passportCode}}
	//key2Col2 := shim.Column{Value: &shim.Column_String_{String_: passportTypeCode}}
	//key2Col3 := shim.Column{Value: &shim.Column_String_{String_: issuerID}}
	key2columns = append(key2columns, key2Col1)

	tableName := providerEnrollmentID + passport_TBL_PREFIX

	rows, err := getRows(&stub, tableName, key2columns)
	if err != nil {
		return nil, fmt.Errorf("Error checking for existing passport, [%v]", err)
	}

	if len(rows) > 0 {
		rowPointer := rows[0]
		row := *rowPointer
		return nil, fmt.Errorf("passport already exists -> " + row.Columns[1].GetString_() + "|" + row.Columns[2].GetString_() + "|" + row.Columns[5].GetString_())
	}
	//Get Transaction TimeStamp
	stampPointer, err := stub.GetTxTimestamp()

	if err != nil {
		return nil, fmt.Errorf("Could not get Transaction timestamp from peer, [%v]", err)

	}

	//Save passport
	timestamp := *stampPointer
	_, err = stub.InsertRow(
		tableName,
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: providerEnrollmentID}},
				&shim.Column{Value: &shim.Column_String_{String_: passportCode}},
				&shim.Column{Value: &shim.Column_String_{String_: passportTypeCode}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedPayload}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerCode}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerID}},
				&shim.Column{Value: &shim.Column_String_{String_: issuerBorderManagement}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedKey}},
				&shim.Column{Value: &shim.Column_String_{String_: passportParams[6]}},
				&shim.Column{Value: &shim.Column_Bool{Bool: issuerVerified}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: encryptedAttachmentURI}},
				&shim.Column{Value: &shim.Column_String_{String_: callerDetails.user}},
				&shim.Column{Value: &shim.Column_Int64{Int64: timestamp.Seconds}},
				&shim.Column{Value: &shim.Column_String_{String_: ""}},
				&shim.Column{Value: &shim.Column_Int64{Int64: 0}},
			},
		})

	fmt.Println(err)

	if err != nil {
		return nil, fmt.Errorf("Could not get save passport, [%v]", err)

	}

	eventPayload := providerEnrollmentID + "|" + passportCode

	//Broadcast 'New ID Issued'
	err = stub.SetEvent(EVENT_NEW_passport_ISSUED, []byte(eventPayload))
	fmt.Println(err)

	if err != nil {
		return nil, fmt.Errorf("Failed to setevent EVENT_NEW_passport_ISSUED, [%v] -> "+eventPayload, err)
	}
	return nil, nil

}

func (t *passportChainCode) Removepassport(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	//Get Caller Details
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	//Check if Tcert has a valid role
	validRoles := hasValidRoles(callerDetails)

	if validRoles == false {
		return nil, fmt.Errorf("Access denied. Unknown role in Tcert -> " + callerDetails.role)
	}

	if len(args) < 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID, passportCode]")
	}
	enrollmentID := args[0]
	passportCode := args[1]

	isProv := isProvider(callerDetails)
	isUser := isUser(callerDetails)

	if isUser == true && callerDetails.userEnrollmentID != args[0] {
		errmsg := "Access Denied. User Role found in TCert but Enrollment ID on certificate don't match"
		fmt.Println(errmsg + "->" + callerDetails.userEnrollmentID)
		return nil, fmt.Errorf(errmsg)
	}

	var columns []shim.Column = []shim.Column{}
	keyCol1 := shim.Column{Value: &shim.Column_String_{String_: passportCode}}
	columns = append(columns, keyCol1)

	if isProv == false && isUser == false {
		keyCol2 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol2)
	}

	tableName := enrollmentID + passport_TBL_PREFIX
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting passport, [%v]", err)
	}
	if len(rowPointers) == 0 {
		return nil, fmt.Errorf("passport does not exist")
	}

	row := *rowPointers[0]

	err = stub.DeleteRow(tableName, []shim.Column{
		shim.Column{Value: &shim.Column_String_{String_: row.Columns[1].GetString_()}},
		shim.Column{Value: &shim.Column_String_{String_: row.Columns[2].GetString_()}},
		shim.Column{Value: &shim.Column_String_{String_: row.Columns[4].GetString_()}},
		shim.Column{Value: &shim.Column_String_{String_: row.Columns[5].GetString_()}},
	})

	if err != nil {
		return nil, fmt.Errorf("Error deleting passport, [%v] -> "+enrollmentID+"|"+passportCode, err)

	}

	return []byte("passport successfully removed"), nil

}

func (t *passportChainCode) GetPassports(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	//Get Caller Details
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	//Check if Tcert has a valid role
	validRoles := hasValidRoles(callerDetails)

	if validRoles == false {
		return nil, fmt.Errorf("Access denied. Unknown role in Tcert -> " + callerDetails.role)
	}

	if len(args) < 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID]")
	}
	enrollmentID := args[0]
	isProv := isProvider(callerDetails)
	isUser := isUser(callerDetails)

	if isUser == true && callerDetails.userEnrollmentID != args[0] {
		errmsg := "Access Denied. User Role found in TCert but Enrollment ID on certificate don't match"
		fmt.Println(errmsg + "->" + callerDetails.userEnrollmentID)
		return nil, fmt.Errorf(errmsg)
	}
	var columns []shim.Column = []shim.Column{}

	if isProv == false && isUser == false { //Its Issuer
		keyCol1 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol1)
	}

	tableName := enrollmentID + passport_TBL_PREFIX
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Passports, [%v]", err)
	}
	var passports []passportMin
	for _, rowPointer := range rowPointers {
		row := *rowPointer
		var passport = passportMin{}
		passport.ProviderEnrollmentID = enrollmentID
		passport.passportCode = row.Columns[1].GetString_()
		passport.passportTypeCode = row.Columns[2].GetString_()
		passport.IssuerCode = row.Columns[4].GetString_()
		passport.IssuerID = row.Columns[5].GetString_()
		passport.IssuerBorderManagement = row.Columns[6].GetString_()
		passport.CreatedBy = row.Columns[11].GetString_()
		passport.CreatedOnTxTimestamp = row.Columns[12].GetInt64()
		passport.LastUpdatedBy = row.Columns[13].GetString_()
		passport.LastUpdatedOnTxTimestamp = row.Columns[14].GetInt64()
		passport.IssuerVerified = row.Columns[9].GetBool()

		passports = append(passports, passport)

	}

	jsonRp, err := json.Marshal(passports)

	if err != nil {
		return nil, fmt.Errorf("Error Getting Passports, [%v]", err)

	}
	fmt.Println(string(jsonRp))

	return jsonRp, nil

}

func (t *passportChainCode) Getpassport(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	//Get Caller Details
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	//Check if Tcert has a valid role
	validRoles := hasValidRoles(callerDetails)

	if validRoles == false {
		return nil, fmt.Errorf("Access denied. Unknown role in Tcert -> " + callerDetails.role)
	}

	if len(args) < 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID, passportCode]")
	}
	enrollmentID := args[0]
	passportCode := args[1]

	isProv := isProvider(callerDetails)
	isUser := isUser(callerDetails)

	if isUser == true && callerDetails.userEnrollmentID != args[0] {
		errmsg := "Access Denied. User Role found in TCert but Enrollment ID on certificate don't match"
		fmt.Println(errmsg + "->" + callerDetails.userEnrollmentID)
		return nil, fmt.Errorf(errmsg)
	}

	var columns []shim.Column = []shim.Column{}
	keyCol1 := shim.Column{Value: &shim.Column_String_{String_: passportCode}}
	columns = append(columns, keyCol1)

	if isProv == false && isUser == false {
		keyCol2 := shim.Column{Value: &shim.Column_String_{String_: callerDetails.issuerID}}
		columns = append(columns, keyCol2)
	}

	tableName := enrollmentID + passport_TBL_PREFIX
	rowPointers, err := getRows(&stub, tableName, columns)

	if err != nil {
		return nil, fmt.Errorf("Error Getting passport, [%v]", err)
	}

	row := *rowPointers[0]
	var passport = passport{}
	passport.ProviderEnrollmentID = enrollmentID
	passport.passportCode = row.Columns[1].GetString_()
	passport.passportTypeCode = row.Columns[2].GetString_()
	passport.EncryptedPayload = encodeBase64(row.Columns[3].GetBytes())
	passport.IssuerCode = row.Columns[4].GetString_()
	passport.IssuerID = row.Columns[5].GetString_()
	passport.IssuerBorderManagement = row.Columns[6].GetString_()
	passport.EncryptedKey = encodeBase64(row.Columns[7].GetBytes())
	passport.MetaData = row.Columns[8].GetString_()
	passport.IssuerVerified = row.Columns[9].GetBool()
	passport.EncryptedAttachmentURI = encodeBase64(row.Columns[10].GetBytes())
	passport.CreatedBy = row.Columns[11].GetString_()
	passport.CreatedOnTxTimestamp = row.Columns[12].GetInt64()
	passport.LastUpdatedBy = row.Columns[13].GetString_()
	passport.LastUpdatedOnTxTimestamp = row.Columns[14].GetInt64()

	jsonRp, err := json.Marshal(passport)

	if err != nil {
		return nil, fmt.Errorf("Error Getting passport, [%v]", err)

	}

	return jsonRp, nil

}

func (t *passportChainCode) GetPublicKey(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {

	//Get Caller Details
	callerDetails, err := readCallerDetails(&stub)
	if err != nil {
		return nil, fmt.Errorf("Error getting caller details, [%v]", err)
	}

	//Check if Tcert has a valid role
	validRoles := hasValidRoles(callerDetails)

	if validRoles == false {
		return nil, fmt.Errorf("Access denied. Unknown role in Tcert -> " + callerDetails.role)
	}

	if len(args) < 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1 -> [enrollmentID]")
	}
	enrollmentID := args[0]

	//Verify that Enrollment ID and Pubic key is not null
	if enrollmentID == "" {
		return nil, errors.New("Provider Enrollment ID  required")
	}

	//Add Public key state
	existingPKBytes, err := stub.GetState(enrollmentID + PUBLIC_KEY_PREFIX)

	if err != nil {
		return nil, fmt.Errorf("Public Key for " + enrollmentID + "  does not exist")
	}

	return existingPKBytes, nil
}
