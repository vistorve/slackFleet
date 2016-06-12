from .. import get_shared_fit

import nose
import mock

def make_type(slot=None, drone=False, charge=False, name="foo"):
    type = {'name': name}
    if slot is not None:
        type['dogma'] = {'effects': [{'effect':{'name': slot}}]}
    elif drone:
        type['description'] = "foo Drone foo"
    elif charge:
        type['dogma'] = {'attributes':[{'attribute':{'name': "chargeSize"}}]}

    return type

def test_parse_type_slot():
    nose.tools.assert_equal(("foo", False, False, get_shared_fit.LOW),
                             get_shared_fit(slot=get_shared_fit.LOW))
    nose.tools.assert_equal(("foo", False, False, get_shared_fit.MED),
                            get_shared_fit(slot=get_shared_fit.MED))
    nose.tools.assert_equal(("foo", False, False, get_shared_fit.HIGH),
                            get_shared_fit(slot=get_shared_fit.HIGH))
    nose.tools.assert_equal(("foo", False, False, get_shared_fit.RIG),
                            get_shared_fit(slot=get_shared_fit.RIG))

def test_parse_type_drone():
    nose.tools.assert_equal(("foo", True, False, None), get_shared_fit(drone=True))

def test_parse_type_charge():
    nose.tools.assert_equal(("foo", False, True, None), get_shared_fit(charge=True))

@mock.patch.object(get_shared_fit, "boto3")
@mock.patch.object(get_shared_fit, "urllib2")
def test_get_type(urllib_mock, boto_mock):
    type_db_mock = mock.Mock()
    type_db_mock.query.return_value = {'Items': []}

    boto_mock.resource.Table.return_value = type_db_mock

    # Type not in db so crest query is run
    get_shared_fit.get_type(123, "crest")

    urllib_mock.url_open.assert_called_with("crest")

    # Is in db so crest query isnt run
    type_db_mock.query.return_value = {'Items': [123,456]}
    urllib_mock.url_open.reset()

    get_shared_fit.get_type(123, "crest")

    nose.tools.assert_equal(0, len(urllib_mock.url_open.call_args_list))
