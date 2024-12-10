from scapy.all import *


def packet_filtering(packet):

    print("ANTES DO FILTRO")
    packet.show()

    if packet.haslayer(Raw):
        packet[Raw].load = filter_brainrot_content(packet).encode()

    print("DEPOIS DO FILTRO")
    packet.show()
    
    # Envia para prox roteador
    
def filter_brainrot_content(packet):
    '''Retorna o novo payload com as palavras proibidas substutuídas por: -'''

    payload = packet[Raw].load.decode(errors='ignore')
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