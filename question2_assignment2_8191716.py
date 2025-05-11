import string

mapping = {
    "V": "E",
    "N": "R",
    "S": "A",
    "X": "T",
    "C": "H",
    "O": "S",
    "A": "N",
    "G": "I",
    "Q": "O",
    "J": "C",
    "U": "L",
    "W": "D",
    "E": "F",
    "R": "K",
    "Z": "M",
    "B": "Y",
    "K": "W",
    "H": "G",
    "I": "U",
    "P": "P",
    "D": "B",
    "L": "J",
    "M": "V",
    "F": "Z",
    "T": "Q",
    "Y": "X"
}
encrypt_string = "SDJWVEHCGLRUZAQPTNOXIMKYBF"
decrypt_string = "NYHBFZIGUCWJVRSPOKAQLEDTXM"

# for index, char in enumerate(string.ascii_uppercase):
#     print(f'"{char}": "{decrypt_string[index]}", ')

encrypt_key = {
    "A": "S",
    "B": "D",
    "C": "J",
    "D": "W",
    "E": "V",
    "F": "E",
    "G": "H",
    "H": "C",
    "I": "G",
    "J": "L",
    "K": "R",
    "L": "U",
    "M": "Z",
    "N": "A",
    "O": "Q",
    "P": "P",
    "Q": "T",
    "R": "N",
    "S": "O",
    "T": "X",
    "U": "I",
    "V": "M",
    "W": "K",
    "X": "Y",
    "Y": "B",
    "Z": "F",
    "\n": "\n",
    " ": " "
}
decrypt_key = {
    "A": "N",
    "B": "Y",
    "C": "H",
    "D": "B",
    "E": "F",
    "F": "Z",
    "G": "I",
    "H": "G",
    "I": "U",
    "J": "C",
    "K": "W",
    "L": "J",
    "M": "V",
    "N": "R",
    "O": "S",
    "P": "P",
    "Q": "O",
    "R": "K",
    "S": "A",
    "T": "Q",
    "U": "L",
    "V": "E",
    "W": "D",
    "X": "T",
    "Y": "X",
    "Z": "M",
    "\n": "\n",
    " ": " "
}

plaintext = """
TOBEO RNOTT OBETH ATIST HEQUE STION WHETH ERTIS NOBLE 
RINTH EMIND TOSUF FERTH ESLIN GSAND ARROW SOFOU TRAGE 
OUSFO RTUNE ORTOT AKEAR MSAGA INSTA SEAOF TROUB LESAN 
DBYOP POSIN GENDT HEMTO DIETO SLEEP NOMOR EANDB YASLE 
EPTOS AYWEE NDTHE HEART ACHEA NDTHE THOUS ANDNA TURAL 
SHOCK STHAT FLESH ISHEI RTOTI SACON SUMMA TIOND EVOUT 
LYTOB EWISH DTODI ETOSL EEPTO SLEEP PERCH ANCET ODREA 
MAYTH EREST HERUB
"""

encrypted_string = ""
for char in plaintext:
    encrypted_string += encrypt_key[char]

print(encrypted_string)

encrypted_string2 = """
XQDVQ NAQXX QDVXC SXGOX CVTIV OXGQA KCVXC VNXGO AQDUV 
NGAXC VZGAW XQOIE EVNXC VOUGA HOSAW SNNQK OQEQI XNSHV 
QIOEQ NXIAV QNXQX SRVSN ZOSHS GAOXS OVSQE XNQID UVOSA 
WDBQP PQOGA HVAWX CVZXQ WGVXQ OUVVP AQZQN VSAWD BSOUV 
VPXQO SBKVV AWXCV CVSNX SJCVS AWXCV XCQIO SAWAS XINSU 
OCQJR OXCSX EUVOC GOCVG NXQXG OSJQA OIZZS XGQAW VMQIX 
UBXQD VKGOC WXQWG VXQOU VVPXQ OUVVP PVNJC SAJVX QWNVS 
ZSBXC VNVOX CVNID
"""

decrypted_string = ""
for char in encrypted_string2:
    decrypted_string += decrypt_key[char]

print(decrypted_string)

decrypted_string2 = """
TOBEO RNOTT OBETH ATIST HEQUE STION WHETH ERTIS NOBLE 
RINTH EMIND TOSUF FERTH ESLIN GSAND ARROW SOFOU TRAGE 
OUSFO RTUNE ORTOT AKEAR MSAGA INSTA SEAOF TROUB LESAN 
DBYOP POSIN GENDT HEMTO DIETO SLEEP NOMOR EANDB YASLE 
EPTOS AYWEE NDTHE HEART ACHEA NDTHE THOUS ANDNA TURAL 
SHOCK STHAT FLESH ISHEI RTOTI SACON SUMMA TIOND EVOUT 
LYTOB EWISH DTODI ETOSL EEPTO SLEEP PERCH ANCET ODREA 
MAYTH EREST HERUB
"""

q1= """KZRNK GJKIP ZBOOB XLCRG BXFAU GJBNG RIXRU XAFGJ 
BXRME MNKNG BURIX KJRXR SBUER ISATB UIBNN RTBUM
NBIGK EBIGR OCUBR GLUBN JBGRL SJGLN GJBOR ISLRS
BAFFO AZBUN RFAUS AGGBI NGLXM IAZRX RMNVL GEANG
CJRUE KISRM BOOAZ GLOKW FAUKI NGRIC BEBRI NJAWB
OBNNO ATBZJ KOBRC JKIRR NGBUE BRINK XKBAF QBROA
LNMRG MALUF BBG"""

mapping_q1 = {
    "B": "E",
    "G": "T",
    "U": "R",
    "R": "A",
    "I": "N",
    "J": "H",
    "K": "I",
    "A": "O",
    "P": "K",
    "N": "S",
    "Z": "W",
    "O": "L",
    "F": "F",
    "C": "C",
    "X": "D",
    "L": "U",
    "E": "M",
    "M": "Y",
    "S": "G",
    "T": "V",
    "W": "P",
    "Q": "J",
    "V": "B",
    "\n": "\n",
    " ": " "
}
q1_output = ""
for char in q1:
    if char not in mapping_q1:
        q1_output += "-"
    else:
        q1_output += mapping_q1[char]

print(q1_output)
