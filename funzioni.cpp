#include "funzioni.h"
#include <iostream>   // cout, cin, cerr
#include <string>     // std::string
#include <sstream>    // stringstream
#include <fstream>    // ifstream, ofstream
#include <bitset>     // bitset
#include <cstdint>    // uint16_t e altri tipi fissi
using namespace std;

//Funzione che converte numero decimale in array di char che sono i bit
void ConvertiIntBinario(int Number, char Array[], size_t dimArray){
    for(size_t i=0; i<dimArray; i++){
        Array[dimArray-1-i] = (Number % 2)? '1' : '0';
        Number/=2;
    }
}

//Funzione che legge il contenuto del file
string LeggiMessaggio(const string& NomeFile) {
    ifstream file(NomeFile); 
    if (!file) {
        cerr << "File non trovato, procedendo alla sua creazione." << endl;
        ofstream creaFile(NomeFile);
        ifstream file(NomeFile);
        return "";
    }
    stringstream buffer;
    buffer << file.rdbuf();
    if (file.fail()) {
        cerr << "Errore nella lettura del file" << endl;
        return "";
    }
    return buffer.str();
}

//Funzione che scrive il contenuto sul file
void ScritturaMessaggio(const string& Contenuto, const string& NomeFile) {
    ofstream file(NomeFile);
    if (!file) {
        cerr << "Errore durante l'apertura del file per la scrittura." << endl;
        return;
    }
    file << Contenuto;
    if (!file) {
        cerr << "Errore durante la scrittura nel file." << endl;
    }
}

//Funzione di input del contenuto
string InputMessaggio(const unsigned int LunghezzaMax) {
    string messaggio;
    cout << "Inserisci un messaggio (max " << LunghezzaMax << " caratteri, senza spazi):" << endl;
    while (true) {
        cin >> messaggio;
        if (messaggio.size() > static_cast<size_t>(LunghezzaMax)) {
            cout << "Messaggio troppo lungo. Reinserisci:" << endl;
        } else {
            break;
        }
    }
    return messaggio;
}

//Funzione di stampa del contenuto
void OutputMessaggio(const string& messaggio) {
    if (!messaggio.empty()) {
        cout << "Messaggio attuale: " << messaggio << endl;
    } else {
        cout << "Nessun messaggio presente." << endl;
    }
}

//Conversione del carattere in binario
string charToBin(char c) {
    return bitset<8>(static_cast<unsigned char>(c)).to_string();
}

//Funzione che converte da stringa a "binario"
string stringToBin(const string& input) {
    string binario;
    binario.reserve(input.size() * 8);
    for (char c : input) {
        binario += charToBin(c);
    }
    return binario;
}

//Conversione da binario a stringa
string binToString(const string& binario) {
    if (binario.size() % 8 != 0) {
		cerr << "Errore: la lunghezza della stringa binaria deve essere un multiplo di 8." << endl;
		return "";
	}
    string risultato;
    risultato.reserve(binario.size() / 8);
    for (size_t i = 0; i < binario.size(); i += 8) {
        bitset<8> cbitset(binario.substr(i, 8));
        char c = static_cast<char>(cbitset.to_ulong());
        risultato += c;
    }
    return risultato;
}

//Conversione dell'indirizzo IP da decimale a binario
void IndirizzoIpBinario(char Address[4][8], const int Numbers[4]) {
    for (int i = 0; i < 4; i++) {
        bitset<8> b(Numbers[i]);
        for (int j = 0; j < 8; j++) {
			Address[i][j] = b[7 - j] ? '1' : '0';
		}
    }
}

//Algoritmo per calcolare il checksum
uint16_t ChecksumAlgorythm(const string& payload) {
    unsigned int somma = 0;
    for (size_t i = 0; i < payload.size(); i++) {
        if (payload[i] == '1') {
            somma += 1 << (i % 16);
        }
    }
    return static_cast<uint16_t>(somma % 65536);
}

//Creazione della lista dinamica delle opzioni
void CreaOpzioni(S_Options *&Testa, int NumElementi, char CF, const char OC[2], const char ON[5]) {
    S_Options* ultimo = NULL;
    for (int i = 0; i < NumElementi; i++) {
        S_Options* nuovo = new S_Options;
        nuovo->CF = CF;
        for (int j = 0; j < 2; j++) {
            nuovo->OC[j] = OC[j];
        }
        for (int j = 0; j < 5; j++) {
            nuovo->ON[j] = ON[j];
        }
        nuovo->next = NULL;
        if (Testa == NULL) {
            Testa = nuovo;
        } else {
            ultimo->next = nuovo;
        }
        ultimo = nuovo;
    }
}

//Restituisce la dimensione dellla lista dinamica delle opzioni
size_t RestituireDim(const S_Options* Testa) {
    size_t count = 0;
    for (const S_Options* tmp = Testa; tmp != NULL; tmp = tmp->next) count++;
    return count;
}

//Creazione del pacchetto
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
    const string& Payload)
{
    Packet.Payload = Payload; // Inserisce il payload
    
    //Version (4 bit)
    Packet.Version[0] = '0';
    Packet.Version[1] = '1';
    Packet.Version[2] = '0';
    Packet.Version[3] = '0';

    //Tos (Type of Service) - 8 bit
    for (int i = 0; i < 3; i++) Packet.ToS.Precedence[i] = TOS[i];
    Packet.ToS.Delay       = TOS[3];
    Packet.ToS.Troghput    = TOS[4];
    Packet.ToS.Reliability = TOS[5];
    Packet.ToS.Monetaty_Cost = TOS[6];
    Packet.ToS.Unused      = TOS[7];

    //ID (16 bit)
    ConvertiIntBinario(ID, Packet.ID, 16);

    //Flags (3 bit)
    Packet.Flags.Unused = Flags[0];
    Packet.Flags.MF     = Flags[1];
    Packet.Flags.DF     = Flags[2];

    //Fragment Offset (13 bit)
    ConvertiIntBinario(static_cast<int>(Precedent), Packet.Fragment_Offset, 13);

    //Time To Live (8 bit)
    ConvertiIntBinario(TTL, Packet.TTL, 8);

    //Protocol (8 bit)
    ConvertiIntBinario(Protocol, Packet.Protocol, 8);

    //Header Checksum (16 bit) calcolato sul payload, considera se deve includere l'intero header
    uint16_t checksum = ChecksumAlgorythm(Packet.Payload);
    ConvertiIntBinario(checksum, Packet.Header_Checksum, 16);

    //Source Address (4x8 bit)
    IndirizzoIpBinario(Packet.Source_Address, Source);

    //Destination Address (4x8 bit)
    IndirizzoIpBinario(Packet.Destination_Address, Destination);

    //Campo Options (lista dinamica)
    Packet.Options = nullptr;  // Inizializzazione a nullptr in C++11+
    CreaOpzioni(Packet.Options, NumOpzioni, OpzioniCF, OpzioniOC, OpzioniON);
    
    //Calcolo Header Length (HLEN) in unità di 32 bit (4 byte)
    //L'header base è 20 byte, ogni opzione ha una dimensione specifica, supponiamo 4 byte per opzione
    size_t optionsLengthBytes = RestituireDim(Packet.Options) * 4; //Adatta se dimensione opzioni differente
    size_t headerLengthBytes = 20 + optionsLengthBytes;
    int headerLengthWords = static_cast<int>(headerLengthBytes / 4); //HLEN in parole da 4 byte
    ConvertiIntBinario(headerLengthWords, Packet.HLEN, 4);

    //Calcolo Total Length (header + payload) in byte
    int totalLength = static_cast<int>(headerLengthBytes + Packet.Payload.size());
    ConvertiIntBinario(totalLength, Packet.Total_Length, 16);
}

//Conversione del pacchetto in striga
string creaDatagramStringaRete(const IpHeader& Packet){
    string Impacchettato;
    Impacchettato.reserve(
        4 + 4 + 3 + 1 + 1 + 1 + 1 + 1 + 16 + 16 + 1 + 1 + 1 + 13 + 8 + 8 + 16 + 
        (4*8) + (4*8) + 
        RestituireDim(Packet.Options) * (1 + 2 + 5) + 
        Packet.Payload.size()
    );
    for(int i=0; i<4; i++) Impacchettato += Packet.Version[i];
    for(int i=0; i<4; i++) Impacchettato += Packet.HLEN[i];
    for (int i=0; i<3; i++) Impacchettato += Packet.ToS.Precedence[i];
    Impacchettato += Packet.ToS.Delay;
    Impacchettato += Packet.ToS.Troghput;
    Impacchettato += Packet.ToS.Reliability;
    Impacchettato += Packet.ToS.Monetaty_Cost;
    Impacchettato += Packet.ToS.Unused;
    for(int i=0; i<16; i++) Impacchettato += Packet.Total_Length[i];
    for(int i=0; i<16; i++) Impacchettato += Packet.ID[i];
    Impacchettato += Packet.Flags.Unused;
    Impacchettato += Packet.Flags.MF;
    Impacchettato += Packet.Flags.DF;
    for(int i=0; i<13; i++) Impacchettato += Packet.Fragment_Offset[i];
    for(int i=0; i<8; i++) Impacchettato += Packet.TTL[i];
    for(int i=0; i<8; i++) Impacchettato += Packet.Protocol[i];
    for(int i=0; i<16; i++) Impacchettato += Packet.Header_Checksum[i];
    for(int i=0; i<4; i++){
        for(int j=0; j<8; j++) Impacchettato += Packet.Source_Address[i][j];
    }
    for(int i=0; i<4; i++){
        for(int j=0; j<8; j++) Impacchettato += Packet.Destination_Address[i][j];
    }
    S_Options *tmp = Packet.Options;
    while(tmp!=NULL){
        Impacchettato += tmp->CF;
        for(int i=0; i<2; i++) Impacchettato += tmp->OC[i];
        for(int i=0; i<5; i++) Impacchettato += tmp->ON[i];
        tmp=tmp->next;
    }
    Impacchettato += Packet.Payload;
    return Impacchettato;
}

//Conversione dell'indirizzo IP da decimale a binario
void IndirizzoMacBinario(char Address[6][8], const int Numbers[6]) {
    for (int i = 0; i < 6; ++i) {
        int byteValue = Numbers[i];
        for (int j = 7; j >= 0; --j) {
            Address[i][j] = (byteValue & 1) ? '1' : '0';
            byteValue /= 2;
        }
    }
}

//Creazione del preambolo (pattern 01010101)
void CreaPreambolo(char Address[7][8]) {
    for (int i = 0; i < 7; ++i) {
        for (int j = 0; j < 8; ++j) {
            Address[i][j] = (j % 2 == 0) ? '0' : '1';
        }
    }
}

//Ooperazione XOR bit a bit tra due stringhe binarie
string xorOperation(const string& num1, const char* num2) {
    string result;
    result.reserve(num1.size());
    for (size_t i = 0; i < num1.size(); i++) {
        result += (num1[i] == num2[i]) ? '0' : '1';
    }
    return result;
}

//Calcolo del CRC
void CRCAlgorythm(char FCS[], const string& messaggioInput, size_t dimFCS, const char polinomio[]) {
    string messaggio = messaggioInput + string(dimFCS - 1, '0');
    string tmp = messaggio.substr(0, dimFCS);
    size_t i = dimFCS;
    while (i <= messaggio.size()) {
        if (tmp[0] == '1') {
            tmp = xorOperation(tmp, polinomio);
        } else {
            tmp = xorOperation(tmp, string(dimFCS, '0').c_str());
        }
        if (i < messaggio.size()) {
            tmp = tmp.substr(1) + messaggio[i];
        } else {
            tmp = tmp.substr(1);
        }
        i++;
    }
    for (size_t j = 0; j < dimFCS - 1; j++) {
        FCS[j] = tmp[j];
    }
}

// Creazione del pacchetto fisico Ethernet
void creaDatagramFisico(Ethernetv2Header& Frame, int Source[6], int Destination[6], const string& Payload) {
    // Inserimento del payload
    Frame.Payload = Payload;

    // Creazione del preambolo (7 byte di alternanza 10101010)
    CreaPreambolo(Frame.Preamble);

    // Inserimento del Start Frame Delimiter (SFD): 10101011 (0xD5)
    ConvertiIntBinario(0xD5, Frame.SFD, 8);

    // Conversione degli indirizzi MAC (6 byte ciascuno)
    IndirizzoMacBinario(Frame.Ssap, Destination);  // Destination MAC
    IndirizzoMacBinario(Frame.Dsap, Source);       // Source MAC

    // Inserimento dell'EtherType: 0x0800 (IPv4)
    ConvertiIntBinario(0x0800, Frame.EtherType, 16);

    // Calcolo del CRC-32 (Frame Check Sequence)
    const char polinomioCRC[] = "100000100110000010001110110110111"; // polinomio CRC-32 in binario
	CRCAlgorythm(Frame.FCS, Frame.Payload, 32, polinomioCRC);
}


//Conversione del pacchetto in striga
string creaDatagramStringaFisico(const Ethernetv2Header& Frame) {
    string Impacchettato;
    Impacchettato.reserve(7 * 8 + 6 * 8 + 6 * 8 + 16 + Frame.Payload.size() + 32);
    
    // Preambolo: 7 byte (7 x 8 bit)
    for (int i = 0; i < 7; ++i)
        for (int j = 0; j < 8; ++j) Impacchettato += Frame.Preamble[i][j];
    // Destination MAC (Dsap): 6 byte (6 x 8 bit)
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j < 8; ++j) Impacchettato += Frame.Dsap[i][j];
            
    // Source MAC (Ssap): 6 byte (6 x 8 bit)
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j < 8; ++j) Impacchettato += Frame.Ssap[i][j];

    // EtherType: 2 byte (16 bit)
    for (int i = 0; i < 16; ++i) Impacchettato += Frame.EtherType[i];

    // Payload: stringa già binaria
    Impacchettato += Frame.Payload;

    // FCS: 4 byte (32 bit)
    for (int i = 0; i < 32; ++i) Impacchettato += Frame.FCS[i];

    return Impacchettato;
}

