# SlackFleet

## Dependencies

 * python 2.7
 * AWS Lambda and DynamoDB

## EVE CREST setup

Sign in to [EVE App Management](https://developers.eveonline.com/) and create a new app or reuse and existing one. You will need to update the settings.py with the following:

 * ClientID
 * ClientSecret

You will also need to enter the API Gateway URI for the sso_redirect lambda function here for the SSO auth to be considered valid by CCP.

## AWS Setup

Basic configuration information for AWS, this assumes a passing familiarity with AWS and isn't an indepth guide to full setup.

Notes:

 * Remeber to always deploy after API Gateway changes so that they actually appear

TODO:
 * Create AWS deploy scripts

### Lambda functions

#### slackFleet_main

The lambda function your slack integration will be communicating with. You will need to encrypt the command token for the slack integration you are connecting to this via aws and place that encrypted token in the ENCRYPTED_EXPECTED_TOKEN in settings.py.

Help from AWS slack lambda template:
```
Follow these steps to configure the slash command in Slack:

  1. Navigate to https://<your-team-domain>.slack.com/services/new

  2. Search for and select "Slash Commands".

  3. Enter a name for your command and click "Add Slash Command Integration".

  4. Copy the token string from the integration settings and use it in the next section.

  5. After you complete this blueprint, enter the provided API endpoint URL in the URL field.


Follow these steps to encrypt your Slack token for use in this function:

  1. Create a KMS key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html.

  2. Encrypt the token using the AWS CLI.
     $ aws kms encrypt --key-id alias/<KMS key name> --plaintext "<COMMAND_TOKEN>"

  3. Copy the base-64 encoded, encrypted key (CiphertextBlob) to the kmsEncyptedToken variable.

  4. Give your function's role permission for the kms:Decrypt action.
     Example:
       {
         "Version": "2012-10-17",
         "Statement": [
           {
             "Effect": "Allow",
             "Action": [
               "kms:Decrypt"
             ],
             "Resource": [
               "<your KMS key ARN>"
             ]
           }
         ]
       }
```

##### Configuration

 * Handler: main.lambda_handler
 * Timeout: 2 minutes, main cause for speed is the caching of fits from CREST
 * Role: One with dynamoDB permissions

##### API Gateway

 * Type: POST
 * Authorization: None
 * Integration Request:
  * Body Mapping template: application/x-www-form-urlencoded :: ```{ "body": $input.json("$") }```

#### slackFleet_sso_redir

The lambda function to handle redirect from EVE SSO, and request the auth and refresh token for a user.

##### Configuration

 * Handler: main.sso_redirect
 * Timeout: 10 seconds
 * Role: One with dynamoDB permissions

##### API Gateway

 * Type: GET
 * Authorization: None
 * Method Request:
  * Query Strings: code,state
 * Integration Request:
  * Body Mapping Template:
   * text/html :: ``` { "code": "$input.params('code')","state": "$input.params('state')"}```
   * application/json :: ```{ "code": "$input.params('code')", "state": "$input.params('state')" }```

#### slackFleet_get_shared_fit

The lambda function to handle the retrieval of shared fits. Returns an HTML for an EFT formatted fit.

##### Configuration

 * Handler: get_shared_fit.lambda_handler
 * Timeout: 10 seconds
 * Role: One with dynamoDB permissions

##### API Gateway

 * Type: GET
 * Authorization: None
 * Method Request:
  * Query Strings: fit
 * Integration Request:
  * Body Mapping Template:
   * text/html :: ```{ "fit_id": "$input.params('fit')"}```
   * application/json :: ```{ "fit_id": "$input.params('fit')"}}```
 * Integration Response:
  * Header Mappings:
   * Content-Type :: text/html
  * Body Mapping Templates:
   * text/html :: ```$input.path('$')```
 * Method Response
  * Https Status: 200
    * Response Header: Content-Type


### dynamoDB

#### users

Table to store all relevant user information.

* Partition key: slack_user_id
* Sort key: eve_user_id

#### shared_fits

Table to store mapping between the shared hash of a fit and the CREST formatted JSON.

* Partition key: fitting_hash

#### fittings

Table to cache fittings for an eve user

* Partition key: eve_user_id
* Sort key: fitting_id