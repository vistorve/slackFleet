from __future__ import print_function

import boto3
from boto3.dynamodb.conditions import Key
import json
from collections import defaultdict
import urllib2

LOW, MID, HIGH, RIG = ("loPower", "medPower", "hiPower", "rigSlot")
valid_slots = {LOW, MID, HIGH, RIG}

def lambda_handler(event, context):
    
    fit_id = event['fit_id']

    dynamo = boto3.resource('dynamodb').Table('shared_fits')

    fit = dynamo.query(KeyConditionExpression=Key('fitting_hash').eq(fit_id))
    if len(fit['Items']) == 0:
        return "Unknown fit"

    html = "<html><body><pre>{}</pre></body></html>".format(convert_to_eft(json.loads(fit['Items'][0]['fit'])))
    #html.replace("\\n", "<br>")
    return html

def parse_type(type_json):
    # find slot
    slot = None
    for effect in type_json['dogma']['effects']:
        if effect['effect']['name'] in valid_slots:
            slot = effect['effect']['name']
            break

    # Determine if charge
    is_charge = False
    for attribute in type_json['dogma']['attributes']:
        if "chargeSize" == attribute['attribute']['name']:
            is_charge = True

    # Determine if drone
    is_drone = "drone" in type_json['description'].lower()

    item_name = type_json['name']

    return item_name, is_drone, is_charge, slot

def get_type(type_id, crest_url):
    """
    Query CREST if the type hasn't been cached yet
    """
    types_db = boto3.resource('dynamodb').Table('CREST_types')

    types = types_db.query(KeyConditionExpression=Key('type_id').eq(type_id))
    if len(types['Items']) == 0:
        data = json.loads(urllib2.urlopen(crest_url).read())
        type_dict = dict(zip(('name', 'is_drone', 'is_charge', 'slot'), parse_type(data)))
        type_dict['type_id'] = type_id
        types_db.put_item(Item=type_dict)
    else:
        type_dict = types['Items'][0]

    return type_dict

def convert_to_eft(crest_json):
    slots = {LOW: defaultdict(int),
             MID: defaultdict(int),
             HIGH: defaultdict(int),
             RIG: defaultdict(int)}

    drone = defaultdict(int)
    charge = defaultdict(int)

    for item in crest_json['items']:
        item_type = get_type(item['type']['id'], item['type']['href'])
        if item_type['slot'] is not None:
            slots[item_type['slot']][item_type['name']] += item['quantity']
        elif item_type['is_drone']:
            drone[item_type['name']] += item['quantity']
        elif item_type['is_charge']:
            charge[item_type['name']] += item['quantity']

    def format_mods(mods_dict, list_multiple=True):
        mods = []
        for mod, quant in mods_dict.iteritems():
            if quant > 1:
                if list_multiple:
                    for i in xrange(quant):
                        mods.append(mod)
                else:
                    mods.append("{} x{}".format(mod, quant))
            else:
                mods.append(mod)
        return "\n".join(mods)

    fit = "[{ship}, {name}]\n\n{low}\n\n{mid}\n\n{high}\n\n{rig}\n\n\n{drone}\n\n\n{cargo}"
    fit = fit.format(ship=crest_json['ship']['name'], name=crest_json['name'],
                     low=format_mods(slots[LOW]), mid=format_mods(slots[MID]),
                     high=format_mods(slots[HIGH]), rig=format_mods(slots[RIG]),
                     drone=format_mods(drone, list_multiple=False),
                     cargo=format_mods(charge, list_multiple=False))

    return fit
