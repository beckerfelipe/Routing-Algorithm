from scapy.all import *
from brainword import *
import chardet

def detect_encoding(data):
    """Detecta a codificação do texto."""
    result = chardet.detect(data)
    return result['encoding']


def packet_filtering(packet):
    print("ANTES DO FILTRO")
    packet.show()

    if packet.haslayer(Raw):
        packet[Raw].load = filter_brainrot_content(packet).encode()

    print("DEPOIS DO FILTRO")
    packet.show()

    send(packet)

def filter_brainrot_content(packet):
    '''Returns the new payload with forbidden words replaced by dashes'''

    raw_data = packet[Raw].load

    # Detecta a codificação do payload
    encoding = detect_encoding(raw_data)

    payload = raw_data.decode(encoding, errors="ignore")  
    words = payload.split()

    forbiddenWords = ['mewing', 'bonesmashing']

    for i in range(len(words)):
        if isWordForbidden(words[i], forbiddenWords):
            words[i] = '-' 

    return " ".join(words)

def isWordForbidden(word, forbiddenWords):
    word = word.lower()

    word = word.replace('0', 'o')
    word = word.replace('1', 'i')
    word = word.replace('3', 'e')
    word = word.replace('4', 'a')
    word = word.replace('5', 's')
    word = word.replace('7', 't')
    word = word.replace('$', 's')

    for forbiddenWord in forbiddenWords:
        if word == forbiddenWord:
            return True

    return False
