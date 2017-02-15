from scapy.all import ASN1_SEQUENCE,ASN1_Class_UNIVERSAL,BERcodec_SEQUENCE,ASN1F_SEQUENCE,ASN1_Packet,ASN1_Codecs,ASN1F_OID,\
    ASN1F_field,ASN1_NULL,ASN1F_enum_INTEGER,ASN1F_SEQUENCE_OF,ASN1F_INTEGER,ASN1F_STRING,ASN1F_CHOICE

class ASN1_Class_SNMP(ASN1_Class_UNIVERSAL):
    name="SNMP"
    PDU_GET = 0xa0
    PDU_NEXT = 0xa1
    PDU_RESPONSE = 0xa2
    PDU_SET = 0xa3
    PDU_TRAPv1 = 0xa4
    PDU_BULK = 0xa5
    PDU_INFORM = 0xa6
    PDU_TRAPv2 = 0xa7

class ASN1_SNMP_PDU_GET(ASN1_SEQUENCE):
    tag=ASN1_Class_SNMP.PDU_GET

class ASN_SNMP_PDU_NEXT(ASN1_SEQUENCE):
    tag=ASN1_Class_SNMP.PDU_NEXT

class BERcodec_SNMP_PDU_GET(BERcodec_SEQUENCE):
    tag=ASN1_Class_SNMP.PDU_GET

class BERcodec_SNMP_PDU_NEXT(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT

class ASN1F_SNMP_PDU_GET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_GET

class ASN1F_SNMP_PDU_NEXT(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_NEXT

SNMP_error = {0: "no_error",
                  1: "too_big",
                  # [...]
                  }

SNMP_trap_types = {0: "cold_start",
                       1: "warm_start",
                       # [...]
                       }

class SNMPvarbind(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(ASN1F_OID("oid", "1.3"),
                                   ASN1F_field("value", ASN1_NULL(0))
                                   )

class SNMPget(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SNMP_PDU_GET(ASN1F_INTEGER("id", 0),
                                       ASN1F_enum_INTEGER("error", 0, SNMP_error),
                                       ASN1F_INTEGER("error_index", 0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )

class SNMPnext(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SNMP_PDU_NEXT(ASN1F_INTEGER("id", 0),
                                        ASN1F_enum_INTEGER("error", 0, SNMP_error),
                                        ASN1F_INTEGER("error_index", 0),
                                        ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                        )



class SNMP(ASN1_Packet):
        ASN1_codec = ASN1_Codecs.BER
        ASN1_root = ASN1F_SEQUENCE(
            ASN1F_enum_INTEGER("version", 1, {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}),
            ASN1F_STRING("community", "public"),
            ASN1F_CHOICE("PDU", SNMPget(),
                         SNMPget, SNMPnext, SNMPresponse, SNMPset,
                         SNMPtrapv1, SNMPbulk, SNMPinform, SNMPtrapv2)
        )

    def answers(self, other):
            return (isinstance(self.PDU, SNMPresponse) and
                    (isinstance(other.PDU, SNMPget) or
                     isinstance(other.PDU, SNMPnext) or
                     isinstance(other.PDU, SNMPset)) and
                    self.PDU.id == other.PDU.id)


    bind_layers(UDP, SNMP, sport=161)
    bind_layers(UDP, SNMP, dport=161)