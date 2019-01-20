from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes

# SETUP
currentApplication = []

TAG_ID_CARD_NUMBER = 1
TAG_ID_CERTIFICATE_SERIAL_NUMBER = 2
TAG_ID_KEY_KCV = 0xC0
TAG_ID_KEY_COUNTER = 0xC1

TAG_ID_DOK_STATE = 0x8B
TAG_ID_DOK_TRY_LIMIT = 0x8C
TAG_ID_DOK_MAX_TRY_LIMIT = 0x8D

TAG_ID_IOK_STATE = 0x82
TAG_ID_IOK_TRY_LIMIT = 0x83
TAG_ID_IOK_MAX_TRY_LIMIT = 0x84

APP_SELECT_PREFIX = [0x00, 0xA4, 0x04, 0x0C] # expects to be amended by  [AppID.length] + AppID
APP_ID_CARD_MANAGEMENT = [0xD2, 0X03, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x02]
APP_ID_FILE_MANAGEMENT = [0xD2, 0x03, 0x10, 0x01, 0x00, 0x01, 0x03, 0x02, 0x01, 0x00]

FILE_ID_CERTIFICATE_AUTHORIZATION = 0x0132
FILE_ID_CERTIFICATE_IDENTIFICATION = 0x0001

cardtype = AnyCardType()
cardrequest = CardRequest( timeout=1, cardType=cardtype )
cardservice = cardrequest.waitforcard()
cardservice.connection.connect()
#cd print(toHexString(cardservice.connection.getATR()))

def trace_command(apdu):
    print('sending ' + toHexString(apdu))

def trace_response( response, sw1, sw2 ):
    if None==response: response=[]
    print('response: ', toHexString(response), ' status words: ', "%x %x" % (sw1, sw2))

def isValidIOK(input):
    if len(str(input)) < 4 or len(str(input)) > 10:
        return True
    else:
        return False

def isValidDOK(input):
    if len(str(input)) < 4 or len(str(input)) > 10:
        return True
    else:
        return False

def getData(tagId, authId):
    authId = authId << 4
    request = [0x80, 0xCA, (authId | 1), (authId | tagId), 0x00]

    trace_command(request)
    response, sw1, sw2 = cardservice.connection.transmit(request)
    #trace_response(response, sw1, sw2)

    if ((sw1 == 0x90) and (sw2 == 0x00)):
        return response
    elif (sw1 == 0x6c):
        request[len(request)-1] = sw2
        response, sw1, sw2 = cardservice.connection.transmit(request)
        if ((sw1 == 0x90) and (sw2 == 0x00)):
            return response
    return

def selectApplication(appId):
    if (currentApplication == appId): # replace with prior check from the card
        print('Applet already selected')
        return True
    else:
        selectApplet = APP_SELECT_PREFIX + [len(appId)] + appId
        response, sw1, sw2 = cardservice.connection.transmit(selectApplet)
        #trace_response(response, sw1, sw2)
        if ((sw1 == 0x90) and (sw2 == 0x00)):
            #print('Applet changed to: ' + str(appId))

            return True
        else:
            return False

def getCardNumber():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_CARD_NUMBER, 0)
        if (response):
            return bytearray(response).decode()
    return

def getSerialNumber():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_CERTIFICATE_SERIAL_NUMBER, 0)
        if (response):
            #return bytearray(response).decode('windows-1252')
            return response
    return

def getKeyChecksumValue():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_KEY_KCV, 1)
        if (response):
            #return bytearray(response).decode('cp1250')
            return response
    return

def getDokState():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_DOK_STATE, 0)
        if (response):
            if (response == [1]):
                return 0 # unlocked
            elif (response == [4]):
                return 1 # blocked
    return

def getDokTryLimit():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_DOK_TRY_LIMIT, 0)
        if (response):
            return response
    return -1

def getDokMaxTryLimit():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_DOK_MAX_TRY_LIMIT, 0)
        if (response):
            return response
    return -1

def getIokState():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_IOK_STATE, 0)
        if (response):
            if (response == [1]):
                return 0  # unlocked
            elif (response == [4]):
                return 1  # blocked
    return

def getIokTryLimit():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_IOK_TRY_LIMIT, 0)
        if (response):
            return response
    return -1

def getIokMaxTryLimit():
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        response = getData(TAG_ID_IOK_MAX_TRY_LIMIT, 0)
        if (response):
            return response
    return -1

# PIN Type IOK = 0; DOK = 1;
def changePIN(PINType, oldPIN, newPIN):
    securityCode = 0

    if not oldPIN or not newPIN:
        raise ValueError('PIN cannot be null')

    if (PINType == 0):
        securityCode = 0x11
        if not isValidIOK(newPIN) or not isValidIOK(oldPIN):
            raise ValueError('Invalid length of new PIN')

    elif (PINType == 1):
        securityCode = 0x10
        if not isValidDOK(newPIN) or not isValidDOK(oldPIN):
            raise ValueError('Invalid length of new PIN')

    else:
        raise ValueError('Unsupported PIN change request')

    return changeOrUnblockPIN('different value', securityCode, oldPIN, newPIN)

def unblockIOK(dokPIN, newIOKPIN):
    securityCode = 0x11

    if not dokPIN or not newIOKPIN:
        raise ValueError('PIN cannot be null')
    if not isValidDOK():
        raise ValueError('Invalid length of DOK')
    if not isValidIOK():
        raise ValueError('Invalid length of new IOK PIN')

    return changeOrUnblockPIN('unblock', securityCode, dokPIN, newIOKPIN) #TODO: change this

def changeOrUnblockPIN(reason, securityCode, pinA, pinB):
    if selectApplication(APP_ID_CARD_MANAGEMENT):
        request = [0x00] * 5
        request[0] = 0x00
        request[1] = 0x24
        if reason == 'different value':
            request[2] = 0x00
        elif reason == 'unblock':
            request[2] = 0x01
        request[3] = securityCode
        request[4] = 20

        request += list(bytes(str(pinA), encoding='utf-8'))
        if len(request) < 15:
            request += [0x00] * (15-len(request))

        request += list(bytes(str(pinB), encoding='utf-8'))
        if len(request) < 25:
            request += [0x00] * (25 - len(request))

        trace_command(request)
        print(len(request))
        response, sw1, sw2 = cardservice.connection.transmit(request)
        print(response)
        print (sw1)
        print (sw2)

        # if () (sw1 == 0x90) and (sw2 == 0x00)):
        #     return response

 # TODO:
 # def encryptoAPDU
 # def getCertificate
 # def readFile
 # def createEncryptionToken