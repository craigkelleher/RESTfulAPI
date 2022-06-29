# Craig Kelleher
# final project

from google.cloud import datastore
from flask import Flask, request, render_template, session
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth.transport import requests
import json
import string
import random
import requests
import constants

app = Flask(__name__)
client = datastore.Client()
clientID = "105716160676-rpps38eu80c5t5g8tqj67qua8rs9iq23.apps.googleusercontent.com"
clientSecret = "obNt7CSHrCqZz06JgNSlo_dh"
oauthURL = "https://accounts.google.com/o/oauth2/v2/auth"
redirect_URI = "https://kellehec-project.appspot.com/oauth"
scope = ['https://www.googleapis.com/auth/userinfo.email',
         'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(clientID, redirect_uri=redirect_URI, scope=scope)


# random value for state source https://pythontips.com/2013/07/28/generating-a-random-string/
def generateState(length=30, chars=string.ascii_letters + string.digits):
    return "".join(random.choice(chars) for x in range(length))


@app.route('/')
def Homepage():
    state = generateState()
    session['state'] = state
    link_url = oauthURL + "?response_type=code&client_id=" + clientID + \
               "&redirect_uri=" + request.url + "oauth" + \
               "&scope=profile email&state=" + state
    return render_template('welcome.html', startURL=link_url)


@app.route('/oauth')
def oauth():
    code = request.args.get('code')
    state = request.args.get('state')
    if state != session['state']:
        error = {'Error': "State does not match"}
        return json.dumps(error), 401
    header = {'Content-Type': 'application/x-www-form-urlencoded'}
    data1 = {
        'code': code,
        'client_id': clientID,
        'client_secret': clientSecret,
        'redirect_uri': request.base_url,
        'grant_type': 'authorization_code'}
    r = requests.Request()
    results = r.__call__("https://oauth2.googleapis.com/token", method='POST', body=data1, headers=header)
    get_token = json.loads(results.data)
    jwt_token = get_token['id_token']
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    for e in results:
        if e['user_id'] == user_id:
            return render_template('user_info.html', id_token=jwt_token)
    new_user = datastore.entity.Entity(key=client.key(constants.users))
    new_user.update(
        {'user_id': user_id,
         'email': id_info['email'],
         'name': id_info['name'],
         'boats': []})
    client.put(new_user)
    print(new_user)
    return render_template('user_info.html', id_token=jwt_token)


@app.route('/boats', methods=['POST'])
def create_boats():
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    if not request.data:
        error = {'Error': "The body of the request is missing"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    content = request.get_json(force=True)
    if "name" not in content or "type" not in content or "length" not in content:
        error = {"Error": "The request object is missing at least one of the required attributes"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    if not request.data:
        error = {"Error": "The body of the request is missing"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    new_boat = datastore.entity.Entity(key=client.key(constants.boats))
    new_boat.update({"name": content["name"], "type": content["type"],
                     "length": content["length"], "owner": user_id,
                     "loads": []})
    client.put(new_boat)
    boat_url = request.url + "/" + str(new_boat.key.id)
    new_boat["self"] = boat_url
    new_boat["id"] = new_boat.key.id
    newBoat = json.dumps(new_boat)
    return newBoat, 201, {'Content-Type': 'application/json'}


@app.route('/boats', methods=['GET'])
def view_all_boats():
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    if 'Authorization' not in request.headers:
        boat_url = request.url
        query = client.query(kind=constants.boats)
        total_boats = list(query.fetch())
        num_boats = len(total_boats)
        query = client.query(kind=constants.boats)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(
                q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = boat_url + "/" + str(e.key.id)
        output = {"boats": results, 'total number of boats': num_boats}
        if next_url:
            output["next"] = next_url
        return json.dumps(output), 200, {'Content-Type': 'application/json'}
    else:
        jwt_token = request.headers['Authorization'].replace('Bearer ', '')
        try:
            id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
            user_id = id_info['sub']
        except ValueError:
            error = {"Error": "Either this user is not in the database or the JWT is missing"}
            return json.dumps(error), 401, {'Content-Type': 'application/json'}
        except TypeError:
            error = {"Error": "Either this user is not in the database or the JWT is missing"}
            return json.dumps(error), 401, {'Content-Type': 'application/json'}
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        if not any(d['user_id'] == user_id for d in results):
            error = {'Error': 'Either this user is not in the database or the JWT is missing'}
            return json.dumps(error), 401, {'Content-Type': 'application/json'}
        query = client.query(kind=constants.boats)
        query.add_filter('owner', '=', user_id)
        user_boats = list(query.fetch())
        return json.dumps(user_boats), 200, {'Content-Type': 'application/json'}


@app.route('/boats/<boat_id>', methods=['GET'])
def view_boat(boat_id):
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(boat_key)
    if not boat:
        error = {"Error": "No boat with this boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    boat_url = request.url
    boat["self"] = boat_url
    boat["id"] = boat.key.id
    get_next_boat = json.dumps(boat)
    return get_next_boat, 200, {'Content-Type': 'application/json'}


@app.route('/boats/<boat_id>', methods=['PATCH'])
def edit_boat(boat_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(),clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        error = {"Error": "No boat with this boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if user_id != boat["owner"]:
        error = {"Error": "User is not Owner of boat"}
        return json.dumps(error), 403, {'Content-Type': 'application/json'}
    if not request.data:
        error = {"Error": "The body of the request is missing"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    content = request.get_json(force=True)
    if 'name' in content.keys():
        boat.update({"name": content["name"]})
    if 'type' in content.keys():
        boat.update({"type": content["type"]})
    if 'length' in content.keys():
        boat.update({"length": content["length"]})
    client.put(boat)
    boat["self"] = request.url
    boat["id"] = boat.key.id
    updated_boat = json.dumps(boat)
    return updated_boat, 200, {'Content-Type': 'application/json'}


@app.route('/boats/<boat_id>', methods=['DELETE'])
def delete_boat(boat_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {
            "Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        error = {"Error": "No boat with this boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if user_id != boat["owner"]:
        error = {"Error": "User is not Owner of boat"}
        return json.dumps(error), 403, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.loads)
    results = list(query.fetch())
    for e in results:
        if e["carrier"] == boat.key.id:
            e["carrier"] = None
    client.put_multi(results)
    client.delete(boat_key)
    return "", 204

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT'])
def assign_load_to_boat(boat_id, load_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        error = {"Error": "No boat with that boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if user_id != boat["owner"]:
        error = {"Error": "User is not Owner of boat"}
        return json.dumps(error), 403, {'Content-Type': 'application/json'}
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if not load:
        error = {"Error": "No load with that load_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if load["carrier"] is not None:
        error = {"Error": "A load with that load_id is already assigned to another boat"}
        return json.dumps(error), 403, {'Content-Type': 'application/json'}
    load["carrier"] = boat.key.id
    client.put(load)
    if 'loads' in boat.keys():
        boat['loads'].append(load.key.id)
    client.put(boat)
    return '', 204


@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_loads_for_boat(boat_id):
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        error = {"Error": "No boat with that boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    load_list = []
    if 'loads' in boat.keys():
        for lid in boat["loads"]:
            load_key = client.key(constants.loads, int(lid))
            load_list.append(load_key)
        results = client.get_multi(load_list)
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + "loads/" + str(e.key.id)
        output = {"loads": results}
        return (json.dumps(output)), 200, {'Content-Type': 'application/json'}
    else:
        return json.dumps([])


@app.route('/boats/<boat_id>/loads/<load_id>', methods=['DELETE'])
def remove_load_boat(boat_id, load_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if not boat:
        error = {"Error": "No boat with this boat_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if user_id != boat["owner"]:
        error = {"Error": "User is not Owner of boat"}
        return json.dumps(error), 403, {'Content-Type': 'application/json'}
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if not load:
        error = {"Error": "No load with that load_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if load['carrier'] == boat.key.id:
        load['carrier'] = None
        client.put(load)
        if 'loads' in boat.keys():
            boat['loads'].remove(int(load_id))
            client.put(boat)
        return '', 204
    else:
        error = {"Error": "No load with this load_id is on the boat with this boat_id"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}


@app.route('/loads', methods=['POST'])
def create_loads_post():
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    content = request.get_json()
    if "weight" not in content or "content" not in content or "destination" not in content:
        error = {"Error": "The request object is missing at least one of the required attributes"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    if not request.data:
        error = {"Error": "The body of the request is missing"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    new_load = datastore.entity.Entity(key=client.key(constants.loads))
    new_load.update(
        {"weight": content["weight"], "content": content["content"],
         "destination": content["destination"], "carrier": None})
    client.put(new_load)
    load_url = request.url + "/" + str(new_load.key.id)
    new_load["self"] = load_url
    new_load["id"] = new_load.key.id
    new_loads = json.dumps(new_load)
    return new_loads, 201, {'Content-Type': 'application/json'}


@app.route('/loads', methods=['GET'])
def view_all_loads_get():
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    load_url = request.url
    query = client.query(kind=constants.loads)
    total_loads = list(query.fetch())
    num_of_loads = len(total_loads)
    query = client.query(kind=constants.loads)
    q_limit = int(request.args.get('limit', '5'))
    q_offset = int(request.args.get('offset', '0'))
    g_iterator = query.fetch(limit=q_limit, offset=q_offset)
    pages = g_iterator.pages
    results = list(next(pages))
    if g_iterator.next_page_token:
        next_offset = q_offset + q_limit
        next_url = request.base_url + "?limit=" + str(
            q_limit) + "&offset=" + str(next_offset)
    else:
        next_url = None
    for e in results:
        e["id"] = e.key.id
        e["self"] = load_url + "/" + str(e.key.id)
    output = {"loads": results, "total number of loads": num_of_loads}
    if next_url:
        output["next"] = next_url
    return json.dumps(output), 200, {'Content-Type': 'application/json'}


@app.route('/loads/<load_id>', methods=['GET'])
def view_load_get(load_id):
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(load_key)
    if not load:
        error = {"Error": "No load with this load_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    load_url = request.url
    load["self"] = load_url
    load["id"] = load.key.id
    getLoad = json.dumps(load)
    return getLoad, 200, {'Content-Type': 'application/json'}


@app.route('/loads/<load_id>', methods=['PATCH'])
def edit_load_patch(load_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}
    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(), clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if not request.data:
        error = {"Error": "The body of the request is missing"}
        return json.dumps(error), 400, {'Content-Type': 'application/json'}
    content = request.get_json(force=True)
    if not load:
        error = {"Error": "No load with this load_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if 'weight' in content.keys():
        load.update({"weight": content["weight"]})
    if 'content' in content.keys():
        load.update({"content": content["content"]})
    if 'destination' in content.keys():
        load.update({"destination": content["destination"]})
    client.put(load)
    load["self"] = request.url
    load["id"] = load.key.id
    updated_load = json.dumps(load)
    return updated_load, 200, {'Content-Type': 'application/json'}


@app.route('/loads/<load_id>', methods=['DELETE'])
def loads_delete(load_id):
    if 'Authorization' not in request.headers:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    if 'application/json' not in request.accept_mimetypes:
        error = {'Error': "Requested MIMEtype is not allowed by this method"}
        return json.dumps(error), 406, {'Content-Type': 'application/json'}

    jwt_token = request.headers['Authorization'].replace('Bearer ', '')
    try:
        id_info = id_token.verify_oauth2_token(jwt_token, requests.Request(),
                                              clientID)
        user_id = id_info['sub']
    except ValueError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    except TypeError:
        error = {"Error": "Either this user is not in the database or the JWT is missing"}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    if not any(d['user_id'] == user_id for d in results):
        error = {'Error': 'Either this user is not in the database or the JWT is missing'}
        return json.dumps(error), 401, {'Content-Type': 'application/json'}
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(load_key)
    if not load:
        error = {"Error": "No load with this load_id exists"}
        return json.dumps(error), 404, {'Content-Type': 'application/json'}
    if load["carrier"] is not None:
        boat_id = load["carrier"]
        boat_key = client.key(constants.boats, boat_id)
        boat = client.get(boat_key)
        if "loads" in boat.keys():
            boat["loads"].remove(int(id))
            client.put(boat)
    client.delete(load_key)
    return '', 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)