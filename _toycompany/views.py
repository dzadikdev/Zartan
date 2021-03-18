import logging
import requests
import json
import random
import string

# import functions
from flask import render_template, session, request, redirect, url_for
from flask import Blueprint
from utils.udp import SESSION_INSTANCE_SETTINGS_KEY, get_app_vertical, apply_remote_config
from utils.okta import OktaAdmin, OktaAuth
from config.app_config import default_settings
from utils.email import Email

from GlobalBehaviorandComponents.validation import is_authenticated, get_userinfo

logger = logging.getLogger(__name__)

# set blueprint
toycompany_views_bp = Blueprint(
    'toycompany_views_bp',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='static')


# Required for Login Landing Page
@toycompany_views_bp.route("/profile")
@apply_remote_config
@is_authenticated
def toycompany_profile():
    logger.debug("toycompany_profile()")
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])
    return render_template(
        "{0}/profile.html".format(get_app_vertical()),
        templatename=get_app_vertical(),
        user_info=get_userinfo(),
        user_info2=user,
        config=session[SESSION_INSTANCE_SETTINGS_KEY])


# Required for Login Landing Page
@toycompany_views_bp.route("/chat")
@apply_remote_config
@is_authenticated
def toycompany_chat():
    logger.debug("toycompany_chat()")
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])

    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])

    kws = SuperAwesomeAPI()
    kws_userinfo = kws.check_permissions(user["profile"]["sa_id"])
    logger.debug(kws_userinfo)

    if "Chat" in kws_userinfo and not kws_userinfo["Chat"] == None:
        canchat = kws_userinfo["Chat"]
    else:
        kws_usertoken = kws.client_authtoken()
        kws.request_permission(token=kws_usertoken, user_id=user["profile"]["sa_id"], permission_name="Chat")
        canchat = None

    return render_template(
        "toycompany/chat.html",
        templatename=get_app_vertical(),
        user_info=get_userinfo(),
        user_info2=user,
        canchat=canchat,
        config=session[SESSION_INSTANCE_SETTINGS_KEY])


# Required for Login Landing Page
@toycompany_views_bp.route("/callback")
@apply_remote_config
@is_authenticated
def toycompany_callback():
    logger.debug("toycompany_callback()")

    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])

    code = request.args.get("code")

    kws = SuperAwesomeAPI()
    kws_usertoken = kws.user_token(code)
    kws.request_permission(token=kws_usertoken, user_id=user["profile"]["sa_id"], permission_name="Chat")

    return redirect(url_for("toycompany_views_bp.toycompany_chat", _external=True, _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"]))


# Required for Registration Page
@toycompany_views_bp.route("/registration")
@apply_remote_config
def toycompany_registration_bp():
    logger.debug("Registration")
    return render_template(
        "toycompany/registration.html",
        templatename=get_app_vertical(),
        config=session[SESSION_INSTANCE_SETTINGS_KEY],
        _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"])


@toycompany_views_bp.route("/registration-check", methods=["POST"])
@apply_remote_config
def toycompany_registration_check():
    logger.debug("toycompany_registration_check()")

    DOBDay = request.form.get('DOBDay')
    DOBMonth = request.form.get('DOBMonth')
    DOBYear = request.form.get('DOBYear')
    dob = request.form.get('DOBYear') + "-" + request.form.get('DOBMonth') + "-" + request.form.get('DOBDay')
    country = request.form.get('country')
    username = request.form.get('username')
    password = request.form.get('password')
    dob = DOBYear + "-" + DOBMonth + "-" + DOBDay

    kws = SuperAwesomeAPI()
    checkage = kws.check_age(country=country, dob=dob)
    isMinor = checkage['isMinor']

    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_data = {
        "profile": {
            "login": username,
            "dob": dob,
            "email": username + "@example.com",
            "countryCode": country,
            "isminor": str(isMinor),
        },
        "credentials": {
            "password": {"value": password}
        }
    }

    user_create_response = okta_admin.create_user(user=user_data, activate_user='true')
    okta_auth = OktaAuth(session[SESSION_INSTANCE_SETTINGS_KEY])
    loginresponse = okta_auth.authenticate(username=username, password=password)
    newsession = loginresponse['sessionToken']

    if "id" not in user_create_response:
        msg = "Failed to get a valid response from Okta Create User: user_data:{0} user_create_response:{1}".format(user_data, user_create_response)
        redirect(
            url_for("toycompany_views_bp.toycompany_registration_bp", _external=True, _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"]),
            message=msg)

    redirecturl = request.host_url.replace("http://", "{0}://".format(session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"]))

    return redirect(default_settings["okta_org_name"] + "/login/sessionCookieRedirect?token=" + newsession + "&redirectUrl=" + redirecturl)


@toycompany_views_bp.route("/registration-parent", methods=["POST"])
@apply_remote_config
def toycompany_registration_parent():
    logger.debug("toycompany_registration_parent()")
    
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])
    
    email = request.form.get('parentemail')
    username = request.form.get('parentemail')
    letters = string.ascii_letters
    password = (''.join(random.choice(letters) for i in range(10)))
    
    okta_user_list = okta_admin.get_user_list_by_search("profile.login+eq+\"" + email + "\"")
    if okta_user_list:
        okta_user = okta_user_list[0]

    else:
        user_data = {
            "profile": {
                "login": username,
                "email": email,
            },
            "credentials": {
                "password": {"value": password}
            }
        }
        
        okta_user = okta_admin.create_user(user=user_data, activate_user='true')

        EmailServices().emailRegistration(
            recipient={"address": email},
            token=okta_user["id"])
    
    kws = SuperAwesomeAPI()
    kws_createuser = kws.create_child(country=user["profile"]["countryCode"], dob=user["profile"]["dob"], parentemail=email)
    logger.debug(kws_createuser)
    kws_user_id = kws_createuser['id']

    user_data = {
        "profile": {
            "sa_id": kws_user_id,
            "parentemail": email
        }
    }

    okta_admin.update_user(user_id=user["id"], user=user_data)
    okta_admin.create_linked_users(parentid=okta_user["id"], userid=user["id"], name="parent")

    if "id" not in okta_user:
        msg = "Failed to setup Parent: user_data:{0} user_create_response:{1}".format(user_data, okta_user)
        logger.error(msg)
    else:
        msg = "Access Requested"

    return redirect(url_for("toycompany_views_bp.toycompany_chat", _external=True, _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"], message=msg))



@toycompany_views_bp.route("/familymembers")
@apply_remote_config
@is_authenticated
def toycompany_family():
    logger.debug("toycompany_family()")
    user_info = get_userinfo()
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])

    schemas = okta_admin.get_user_schemas()
    nfamily = ""
    if schemas:
        family = "["
        for schema in schemas:
            family = family + "{" + \
                "\"pname\":\"" + schema['primary']['name'] + "\"," + \
                "\"ptitle\":\"" + schema['primary']['title'] + "\"," + \
                "\"aname\":\"" + schema['associated']['name'] + "\"," + \
                "\"atitle\":\"" + schema['associated']['title'] + "\"," + \
                "\"users\": [ "

            users = okta_admin.get_linked_users(user_info['sub'], schema['associated']['name'])

            for user in users:
                userid = user['_links']['self']['href'].rsplit('/', 1)[-1]
                associateduser = okta_admin.get_user(userid)
                family = family + json.dumps(associateduser) + ","

            family = family[:-1] + "]},"

        family = family[:-1] + "]"
        nfamily = json.loads(family)

    return render_template(
        "toycompany/linkedobjects.html",
        templatename=get_app_vertical(),
        user_info=get_userinfo(),
        config=session[SESSION_INSTANCE_SETTINGS_KEY],
        nfamily=nfamily)


@toycompany_views_bp.route("/suspendchild")
@apply_remote_config
@is_authenticated
def toycompany_child_suspend():
    logger.debug("toycompany_child_suspend()")
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_id = request.args.get('user_id')
    suspend_user = okta_admin.suspend_user(user_id)
    user_info2 = okta_admin.get_user(user_id)

    if not suspend_user:
        message = "User {0} {1} Suspended".format(user_info2['profile']['firstName'], user_info2['profile']['lastName'])
    else:
        message = "Error During Suspension"

    return redirect(
        url_for(
            "toycompany_views_bp.toycompany_family",
            _external="True",
            _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"],
            message=message))


@toycompany_views_bp.route("/unsuspendchild")
@apply_remote_config
@is_authenticated
def toycompany_child_unsuspend():
    logger.debug("toycompany_child_unsuspend()")
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_id = request.args.get('user_id')
    unsuspend_user = okta_admin.unsuspend_user(user_id)
    user_info2 = okta_admin.get_user(user_id)

    if not unsuspend_user:
        message = "User {0} {1} Un-Suspended".format(user_info2['profile']['firstName'], user_info2['profile']['lastName'])
    else:
        message = "Error During Un-Suspension"

    return redirect(
        url_for(
            "toycompany_views_bp.gbactoycompany_family_users",
            _external="True",
            _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"],
            message=message))


@toycompany_views_bp.route("/createnewchild")
@apply_remote_config
def toycompany_child_new():
    logger.debug("toycompany_child_new")
    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    parent_id = request.args.get('parent_id')
    linked_name = request.args.get('linked_name')
    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])

    return render_template(
        "toycompany/createchild.html",
        templatename=get_app_vertical(),
        user_info=user_info,
        user_info2=user,
        parent_id=parent_id,
        linked_name=linked_name,
        config=session[SESSION_INSTANCE_SETTINGS_KEY])


@toycompany_views_bp.route("/createchild", methods=["POST"])
@apply_remote_config
def toycompany_child_create():
    logger.debug("toycompany_child_create")

    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    parent_id = request.form.get('parent_id')
    user_info = get_userinfo()
    user = okta_admin.get_user(user_info["sub"])
    linked_name = request.form.get('linked_name')
    dob = request.form.get('DOBYear') + "-" + request.form.get('DOBMonth') + "-" + request.form.get('DOBDay')
    country = request.form.get('country')
    username = request.form.get('username')
    password = request.form.get('password')
    gender = request.form.get('gender')
    parentemail = user["profile"]["email"]

    kws = SuperAwesomeAPI()
    checkage = kws.check_age(country=country, dob=dob)
    isMinor = checkage['isMinor']

    okta_admin = OktaAdmin(session[SESSION_INSTANCE_SETTINGS_KEY])
    user_data = {
        "profile": {
            "login": username,
            "dob": dob,
            "email": username + "@example.com",
            "countryCode": country,
            "gender": gender,
            "parentemail": parentemail,
            "isminor": isMinor,
        },
        "credentials": {
            "password": {"value": password}
        }
    }
    user_create_response = okta_admin.create_user(user=user_data, activate_user='true')

    msg = "Child Created"
    okta_admin.create_linked_users(parentid=parent_id, userid=user_create_response["id"], name=linked_name)

    return redirect(
        url_for(
            "toycompany_views_bp.toycompany_family",
            _external="True",
            _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"],
            message=msg))


# Class containing email services and formats
class EmailServices:

    # Email user and admin when a new user registers successfully
    def emailRegistration(self, recipient, token):
        logger.debug("emailRegistration()")

        app_title = session[SESSION_INSTANCE_SETTINGS_KEY]["settings"]["app_name"]
        activation_link = url_for(
            "gbac_registration_bp.gbac_registration_state_get",
            stateToken=token,
            _external=True,
            _scheme=session[SESSION_INSTANCE_SETTINGS_KEY]["app_scheme"])
        subject = "Welcome to the {app_title}".format(app_title=session[SESSION_INSTANCE_SETTINGS_KEY]["settings"]["app_name"])
        # Send Activation Email to the user
        message = """
            Welcome to the {app_title}!<br /><br />
            Your Chid has requested access to {app_title}.<br /><br />
            Click this link to activate your account <br />
            <a href='{activation_link}'>{activation_link}</a>
            """.format(app_title=app_title, activation_link=activation_link)
        Email.send_mail(subject=subject, message=message, recipients=[recipient])

        return "Complete"


class SuperAwesomeAPI:

    # Email user and admin when a new user registers successfully
    def client_authtoken(self):
        logger.debug("sa_client_authtoken()")
        authheader = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic b2t0YS10ZXN0Ok1aNnBmY2JTblo1VHJKNVBWeVB6c0k1Zll0Nkd1QjA4",
            "Accept": "application/json"
        }

        authurl = "https://richard-test-environment.api.kws.superawesome.tv/oauth/token"

        authbody = {
            "grant_type": "client_credentials"
        }

        rest_response = requests.post(url=authurl, headers=authheader, data=authbody)
        authresponse_json = rest_response.json()
        return authresponse_json['access_token']

    def username_authtoken(self, username, password):
        logger.debug("sa_username_authtoken()")
        authheader = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic b2t0YS10ZXN0Ok1aNnBmY2JTblo1VHJKNVBWeVB6c0k1Zll0Nkd1QjA4",
            "Accept": "application/json"
        }

        authurl = "https://richard-test-environment.api.kws.superawesome.tv/oauth/token"

        authbody = {
            "grant_type": "password",
            "username": username,
            "password": password
        }

        rest_response = requests.post(url=authurl, headers=authheader, data=authbody)
        authresponse_json = rest_response.json()
        logger.debug(authresponse_json)
        return authresponse_json['access_token']

    def user_token(self, code):
        logger.debug("sa_user_token()")
        authheader = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }

        authurl = "https://richard-test-environment.api.kws.superawesome.tv/oauth/token"

        authbody = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "okta-test",
            "client_secret": "MZ6pfcbSnZ5TrJ5PVyPzsI5fYt6GuB08"
        }

        rest_response = requests.post(url=authurl, headers=authheader, data=authbody)
        authresponse_json = rest_response.json()

        return authresponse_json['access_token']

    def get_user_info(self, user_id):
        logger.debug("sa_get_user_info()")
        header = {
            "Authorization": "Bearer " + SuperAwesomeAPI.client_authtoken(self),
        }
        url = "https://richard-test-environment.api.kws.superawesome.tv/v2/apps/349098747/users/" + user_id + "/"

        rest_response = requests.get(url, headers=header)
        response_json = rest_response.json()
        return response_json

    def request_permission(self, token, user_id, permission_name):
        logger.debug("sa_request_permission()")
        permheader = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        }
        permurl = "https://richard-test-environment.api.kws.superawesome.tv/v1/users/" + user_id + "/request-permissions"

        permbody = {"permissions": [permission_name]}
        requests.post(url=permurl, headers=permheader, json=permbody)

    def check_age(self, dob, country):
        logger.debug("sa_check_age()")
        header = {
            "Authorization": "Bearer " + SuperAwesomeAPI.client_authtoken(self),
        }
        url = "https://richard-test-environment.api.kws.superawesome.tv/v1/countries/child-age?country=" + country + "&dob=" + dob

        rest_response = requests.get(url, headers=header)
        response_json = rest_response.json()
        return response_json

    def create_user(self, username, password, dob, country, parentemail, email):
        logger.debug("sa_create_user()")
        header = {
            "Authorization": "Bearer " + SuperAwesomeAPI.client_authtoken(self),
        }

        url = "https://richard-test-environment.api.kws.superawesome.tv/v2/users"

        if parentemail:
            body = {
                "username": username,
                "password": password,
                "dateOfBirth": dob,
                "country": country,
                "parentEmail": parentemail
            }
        else:
            body = {
                "username": username,
                "password": password,
                "dateOfBirth": dob,
                "country": country,
                "email": email
            }
        logger.debug(body)
        rest_response = requests.post(url, headers=header, json=body)
        response_json = rest_response.json()
        return response_json

    def request_appaccess(self, token, username, userid):
        logger.debug("sa_request_appaccess()")
        permheader = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "Accept-Language": "en",
            "Accept": "application/json, text/plain"
        }
        permurl = "https://richard-test-environment.api.kws.superawesome.tv/v1/users/" + str(userid) + "/apps"

        permbody = {"username": username, "appName": "okta-test", "permissions": []}
        request = requests.post(url=permurl, headers=permheader, json=permbody)
        logger.debug(request)
        return ""

    def create_child(self, dob, country, parentemail):
        logger.debug("sa_create_child()")
        header = {
            "Authorization": "Bearer " + SuperAwesomeAPI.client_authtoken(self),
        }

        url = "https://richard-test-environment.api.kws.superawesome.tv/v2/apps/349098747/users"

    
        body = {
            "dateOfBirth": dob,
            "country": country,
            "parentEmail": parentemail,
            "language": "en",
            "permissions": ["Chat"]

        }

        rest_response = requests.post(url, headers=header, json=body)
        response_json = rest_response.json()
        return response_json
        
    def check_permissions(self, sa_id):
        logger.debug("sa_check_permissions()")
        header = {
            "Authorization": "Bearer " + SuperAwesomeAPI.client_authtoken(self),
        }

        url = "https://richard-test-environment.api.kws.superawesome.tv/v2/apps/349098747/users/"+sa_id+"/permissions"

        rest_response = requests.get(url, headers=header)
        response_json = rest_response.json()
        return response_json
