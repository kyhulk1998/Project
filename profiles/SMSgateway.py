###############################################
##   Ozeki NG - SMS Gateway Python example   ##
###############################################

import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
###############################################
###            Ozeki NG informations        ###
###############################################


def sendSmsMessage(recipient, message_body):
    host = "http://127.0.0.1"
    user_name = "admin"
    user_password = "111111"

    ###############################################
    ### Putting together the final HTTP Request ###
    ###############################################

    http_req = host
    http_req += ":9501/api?action=sendmessage&username="
    http_req += urllib.parse.quote(user_name)
    http_req += "&password="
    http_req += urllib.parse.quote(user_password)
    http_req += "&recipient="
    http_req += urllib.parse.quote(recipient)
    http_req += "&messagetype=SMS:TEXT&messagedata="
    http_req += urllib.parse.quote(message_body)

    ################################################
    ####            Sending the message          ###
    ################################################
    get = urllib.request.urlopen(http_req)
    res = get.read().decode("utf-8")
    get.close()
    # x
    ###        Verifying the response            ###
    ##############################################x#
    if res.find("Message accepted for delivery") > 1:
        print("Message successfully sent")
    else:
        print("Message not sent! Please check your settings!")


def recevieSmsMessage():
    host = "http://127.0.0.1"
    user_name = "admin"
    user_password = "111111"
    folder = "inbox"
    limit = "1"
    response = "xml"

    ###############################################
    ### Putting together the final HTTP Request ###
    ###############################################

    http_req = host
    http_req += ":9501/api?action=receivemessage&username="
    http_req += urllib.parse.quote(user_name)
    http_req += "&password="
    http_req += urllib.parse.quote(user_password)
    http_req += "&folder="
    http_req += urllib.parse.quote(folder)
    http_req += "&limit="
    http_req += urllib.parse.quote(limit)
    http_req += "&responseformat="
    http_req += urllib.parse.quote(response)
    print("Waiting...")
    ################################################
    ####            Sending the message          ###
    ################################################
    get = urllib.request.urlopen(http_req)
    res = get.read().decode("utf-8")
    get.close()

    ################################################
    ####       Data Inbox(receiveMessage)       ####
    ################################################

    data = ET.fromstring(res)
    # print(res)
    sender = data.findall("data/message/originator")[0].text
    messagedata = data.findall("data/message/messagedata")[0].text
    return sender, messagedata




