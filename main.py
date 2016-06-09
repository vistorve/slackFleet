import boto3
from boto3.dynamodb.conditions import Key
from base64 import b64decode
from urlparse import parse_qs
import logging
import uuid
import json
import datetime
import urllib2
import itertools

import settings

kms = boto3.client('kms')
expected_token = kms.decrypt(
    CiphertextBlob=b64decode(settings.ENCRYPTED_EXPECTED_TOKEN))['Plaintext']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ValidationError(Exception): pass

def lambda_handler(event, context):
    """
    Lambda handler for main slack integration.
    """
    req_body = event['body']
    params = parse_qs(req_body)
    token = params['token'][0]
    if token != expected_token:
        logger.error("Request token (%s) does not match exptected", token)
        raise Exception("Invalid request token")

    user = params['user_name'][0]
    uid = params['user_id'][0]
    command = params['command'][0]
    channel = params['channel_name'][0]
    command_text = params['text'][0]
    response_url = params['response_url'][0]

    parts = command_text.split(" ")

    if len(parts) > 1:
        command_text = parts[0]
        args = dict(map(lambda x: x.split("="), parts[1:]))
        for k, v in args.iteritems():
            args[k] = v.split("|")
    else:
        args = {}

    try:
        if command_text == "auth":
            return sso_auth(uid)
        elif command_text == "cache":
            cache_fittings(uid, args)
            make_delayed_response(response_url, "emphemeral", "Cache fittings", "Complete!")
        elif command_text == "search":
            fits = get_fittings(uid, args)
            make_delayed_response(response_url, "emphemeral", "Your fittings", fits)
            return "Search Complete!"
        elif command_text == "share":
            shared_fits = share_fits(uid, args)
            make_delayed_response(response_url, "in-channel", "Shared fits", shared_fits)
            return "Share complete!"
        elif command_text == "help":
            return {"text":help()}
        else:
            return "Command unknown."
    except ValidationError, e:
        return e.message

def make_response(response_type, text, values):
    """
    Create the json used for delayed slack responses.

    If values = [(group, title, info), ...] Response will look vaguely like:
    text
    group
       title
         info
       title
         info
    group2
       ....
    """
    attachments = []
    for ship, ship_info in itertools.groupby(values, lambda x: x[0]):
        fields = []
        for ship, name, info in ship_info:
            fields.append({'title': name, 'value': info})
        attachments.append({'pretext': ship, 'fields': fields})
    logger.log(logging.INFO, json.dumps(attachments))
    return json.dumps({"response_type": response_type,
                       "text": text,
                       "attachments": attachments})

def make_delayed_response(response_url, response_type, text, values):
    """
    Send a delayed response to a slack request

    :param response_url: Url to supplied by slack request to send response to
    :param response_type: "emphemeral" or "in-channel"
    :param text: string, header/title of the message
    :param values: [(grouping key, title, info), ...] to be displayed
    """
    req = urllib2.Request(response_url,
                          data=make_response(response_type, text, values),
                          headers={"Content-type": "application/json"})
    urllib2.urlopen(req)

def get_user(uid, args):
    """
    A helper function to retrieve the user item from the dynamodb table for a given
    slack_user_id. Returns the first matching if multiple usernames are passed in args.

    :param uid: string, slack_user_id
    :param args: dict, {'username': [eve username, ...]}

    :returns: user dynamodb entry
    """
    users = boto3.resource('dynamodb').Table('users')

    response = users.query(
        KeyConditionExpression=Key('slack_user_id').eq(uid)
    )
    actual_user = None
    for user in response['Items']:
        if 'username' in args:
            for username in args['username']:
                if username in user['eve_user_name']:
                    actual_user = user
                    break
        else:
            actual_user = user
            break

    if actual_user is None:
        raise ValidationError("Unknown user: {}".format(args['username']))

    return actual_user

def sso_auth(user):
    """
    Return authentication link. Slack user_id is used as the state variable.

    :param user: string, slack user_id

    :returns: CREST SSO sign on url
    """
    message = "Click here: https://login.eveonline.com/oauth/authorize/\
    ?response_type=code&redirect_uri={}&client_id={}&scope=characterFittingsRead\
    &state={}"

    return message.format(settings.REDIRECT_URI, settings.CLIENT_ID, user)

def sso_redirect(event, context):
    """
    Handler for EVE SSO redirect. Gets auth and refresh token using authorization code from SSO.
    This creates the entry for the user in users dynamodb table. The state query string is used
    to track the slack_user_id.

    Lambda function handler
    """
    code = event['code']
    state = event['state']

    users = boto3.resource('dynamodb').Table('users')

    # Get auth token
    req = urllib2.Request("https://login.eveonline.com/oauth/token",
                          data="grant_type=authorization_code&code={}".format(code), 
                          headers={"Authorization": "Basic {}".format(settings.AUTH)})
                          
    auth_resp = json.loads(urllib2.urlopen(req).read())

    # Get character id
    req = urllib2.Request("https://login.eveonline.com/oauth/verify",
                          headers={"Authorization": "Bearer {}".format(auth_resp['access_token'])})
    char_resp = json.loads(urllib2.urlopen(req).read())

    users.put_item(Item={
        'slack_user_id': state,
        'eve_user_id': str(char_resp['CharacterID']),
        'eve_user_name': char_resp['CharacterName'],
        'token': auth_resp['access_token'],
        'expires': auth_resp['expires_in'],
        'refresh_token': auth_resp['refresh_token'],
        'token_update': datetime.datetime.now().strftime("%s")
    })
    
    return "Auth successfull!"

def make_crest_call(req, user):
    """
    Make a CREST call with a reauthentication step if the auth token has timed out

    param req: urllib2.Request object
    param user: result object from querying users dynamodb table

    :returns: data resulting from call.
    """
    req.add_header("Authorization", "Bearer {}".format(user['token']))

    try:
        return urllib2.urlopen(req).read()
    except urllib2.HTTPError, e:
        if e.code != 401:
            raise

        auth_req = urllib2.Request("https://login.eveonline.com/oauth/token",
                                   data="grant_type=refresh_token&refresh_token={}".format(
                                       user['refresh_token']), 
                                   headers={"Authorization": "Basic {}".format(settings.AUTH)})

        auth = json.loads(urllib2.urlopen(auth_req).read())
        users = boto3.resource('dynamodb').Table('users')
        users.put_item(Item={
            'slack_user_id': user['slack_user_id'],
            'eve_user_id': user['eve_user_id'],
            'eve_user_name': user['eve_user_name'],
            'token': auth['access_token'],
            'expires': auth['expires_in'],
            'refresh_token': user['refresh_token'],
            'token_update': datetime.datetime.now().strftime("%s")
        })
        req.add_header("Authorization", "Bearer {}".format(auth['access_token']))
        return urllib2.urlopen(req).read()

def cache_fittings(uid, args):
    """
    Call CREST and cache fittings for user(s)

    param uid: string slack user id that sent the request
    param args: {'username': [eve username, ...]}
    :returns: None
    """
    fittings = boto3.resource('dynamodb').Table('fittings')

    # get user
    user = get_user(uid, args)

    req = urllib2.Request("{}/characters/{}/fittings/".format(settings.CREST_URI,
                                                              user['eve_user_id']))

    read_time = datetime.datetime.now().strftime("%s")
    fits = []
    for fit in json.loads(make_crest_call(req, user))['items']:
        ship = fit['ship']['name']
        name = fit['name']
        fitting_id = fit['fittingID_str']

        # Remove identifying information
        for key in ("fittingID", "fittingID_str", "href"):
            del fit[key]

        fittings.put_item(Item={'eve_user_id': user['eve_user_id'],
                                'fitting_id': fitting_id,
                                'ship': ship,
                                'name': name,
                                'fit': json.dumps(fit),
                                'read_time': read_time})
    
def get_fittings(uid, args):
    """
    Search cached fittings based on arguments

    param uid: string slack user id that sent the request
    param args: Dict with none to all of: {'ship': [ship type, ...], 'name': [ship name, ...],
                                           'module': [module name, ...]}
    :returns: [(ship, name, fitting_id), ...]
    """
    fittings = boto3.resource('dynamodb').Table('fittings')
    
    user = get_user(uid, args)
    
    fittings_req = fittings.query(KeyConditionExpression=Key('eve_user_id').eq(
        user['eve_user_id']))
    fits = []
    for fit in fittings_req['Items']:
        ship = fit['ship']
        name = fit['name']
        fitting_id = fit['fitting_id']
        fit = json.loads(fit['fit'])

        # Filter on ship type
        if 'ship' in args:
            for ship_filter in args['ship']:
                if ship_filter in ship.lower():
                    break
            else:
                continue

        # Filter on ship name
        if 'name' in args:
            for fit_name in args['name']:
                if fit_name in name.lower():
                    break
            else:
                continue

        # Search module names
        if 'module' in args:
            matched_mod = False
            for item in fit['items']:
                for mod_name in args['module']:
                    if mod_name in item['type']['name'].lower():
                        matched_mod = True
                        break
                if matched_mod: break
            else:
                continue

        fits.append((ship, name, fitting_id))

    fits.sort(key=lambda x: x[0])

    return fits

def share_fits(uid, args):
    """
    Create a map of the hash of eve uid and fitting id to crest json. Map is stored
    in a dynamodb table.

    param uid: string slack user id that sent the request
    param args: {'id': [fitting_id, ...]}
    :returns: [(ship, name, API endpoint url), ...]
    """
    user = get_user(uid, args)

    fittings = boto3.resource('dynamodb').Table('fittings')
    shared_fits = boto3.resource('dynamodb').Table('shared_fits')

    eve_user_id = user['eve_user_id']
    fittings_req = fittings.query(KeyConditionExpression=Key('eve_user_id').eq(eve_user_id))

    shared = []
    for fit in fittings_req['Items']:
        if fit['fitting_id'] not in args['id']: continue

        fit_hash = str(hash((eve_user_id, fit['fitting_id'])))
        shared_fits.put_item(Item={'fitting_hash': fit_hash,
                                   'fit': fit['fit']})
        shared.append((fit['ship'], fit['name'], settings.SHARE_ENDPOINT.format(fit_hash)))

    return shared

def help():
    help_msg = """
    Available commands:
       auth : Call this first and follow link to use SSO to authenticate.
       cache : Call this second to cache all of the fits on authenticated users.
       search : Search your fittings, possible keywords are: username, ship, name, module
       share : Share select fittings, keywords are id

    Commands are given in the form /fitting [command] [keyword]=[arg1]|[arg2]|...
    you can give as many keywords as you like. Arguments to keywords can be OR-ed by
    delimiting them with a pipe "|" character.

    NOTES:
       1. The auth command only needs to be called once per eve user you want to use
       2. The cache command should only be called when you want to read the fittings from
          CREST. The fittings are stored so you only need to call it the first time and if
          you alter fittings.
       3. Search arguments are case insensitive and can match any part of the target string

    Example call sequence:

    /fleet search username=lucy ship=firetail|taranis name=dual

    This would return all fits from Lucy Dearheart with a ship type of firetail or taranis
    with the word "dual" in the fitting name. The list would look something like:
    Republic Fleet Firetail
       dual prop ac
       123456790

    To share this fit in EFT form with someone you would do:
    /fleet share id=12345690

    Which would return you a link that when browsed to will give an EFT format of your fit.
    Anyone may view this link and it will exist forever.
"""
    return help_msg
