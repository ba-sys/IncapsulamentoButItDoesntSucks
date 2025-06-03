#ifndef FUNZIONI_H
#define FUNZIONI_H
#include <string>
using namespace std;
// PARTE DEL LIVELLO RETE

struct S_TOS {
    char Precedence[3];
    char Delay;
    char Troghput;
    char Reliability;
    char Monetaty_Cost;
    char Unused;
};

struct S_Flags {
    char Unused;
    char DF;
    char MF;
};

struct S_Options {
    char CF;
    char OC[2];
    char ON[5];
    S_Options* next;
};

struct IpHeader {
    char Version[4];
    char HLEN[4];
    S_TOS ToS;
    char Total_Length[16];
    char ID[16];
    S_Flags Flags;
    char Fragment_Offset[13];
    char TTL[8];
    char Protocol[8];
    char Header_Checksum[16];
    char Source_Address[4][8];
    char Destination_Address[4][8];
    S_Options* Options;
    string Payload;
};

// PARTE LIVELLO COLLEGAMENTO

struct Ethernetv2Header {
    char Preamble[7][8];
    char SFD[8];
    char Dsap[6][8];
    char Ssap[6][8];
    char EtherType[16];
    string Payload;
    char FCS[32];
};

// Funzioni - prototipi

void ConvertiIntBinario(int Number, char Array[], size_t dimArray);

string LeggiMessaggio(const string& NomeFile);

void ScritturaMessaggio(const string& Contenuto, const string& NomeFile);

string InputMessaggio(const unsigned int LunghezzaMax);

void OutputMessaggio(const string& messaggio);

string charToBin(char c);

string stringToBin(const string& input);

string binToString(const string& binario);

void IndirizzoIpBinario(char Address[4][8], const int Numbers[4]);

uint16_t ChecksumAlgorythm(const string& payload);

void CreaOpzioni(S_Options *&Testa, int NumElementi, char CF, const char OC[2], const char ON[5]);

size_t RestituireDim(const S_Options* Testa);

void creaDatagramRete(
    IpHeader &Packet, 
    const char TOS[8], 
    int ID, 
    const char Flags[3], 
    size_t Precedent, 
    int TTL, 
    int Protocol,
    const int Source[4], 
    const int Destination[4], 
    int NumOpzioni, 
    char OpzioniCF, 
    const char OpzioniOC[2], 
    const char OpzioniON[5],  
    const string& Payload);

string creaDatagramStringaRete(const IpHeader& Packet);

void IndirizzoMacBinario(char Address[6][8], const int Numbers[6]);

void CreaPreambolo(char Address[7][8]);

string xorOperation(const string& num1, const char* num2);

void CRCAlgorythm(char FCS[], const string& messaggioInput, size_t dimFCS, const char polinomio[]);

void creaDatagramFisico(Ethernetv2Header& Frame, int Source[6], int Destination[6], const string& Payload);

string creaDatagramStringaFisico(const Ethernetv2Header& Frame);

#endif // FUNZIONI_H
