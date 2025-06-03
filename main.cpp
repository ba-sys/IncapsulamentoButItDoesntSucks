#include "funzioni.h"
#include <string>
#include <iostream>
using namespace std;

int main() {
	
	//Dimensione del buffer
	const unsigned int lunghezzaMax = 11520;
	//Nomi dei file di input e output
	const string NomeFileInput = "Input.txt";
	const string NomeFileInputBinario = "InputBinario.txt";
	const string NomeFileOutputRete = "Rete.txt";
	const string NomeFileOutputFisico = "Fisico.txt";
	
	//Caricamento del payload
    string ContenutoFileInput = LeggiMessaggio(NomeFileInput);
    if (ContenutoFileInput.empty()){
		ScritturaMessaggio(InputMessaggio(lunghezzaMax), NomeFileInput);
		ContenutoFileInput = LeggiMessaggio(NomeFileInput);
	}
    OutputMessaggio(ContenutoFileInput);
    
    //Conversione in stringa binaria
    cout<<"Conversione in stringa binaria in corso..."<<endl;
    const string ContenutoFileInputBinario = stringToBin(ContenutoFileInput);
	ScritturaMessaggio(ContenutoFileInputBinario, NomeFileInputBinario);
	cout<<"Conversione in stringa binaria completata"<<endl;
	
	//Livello Rete
	cout<<"Creazione pdu rete..."<<endl;
    IpHeader pacchettoIp;
    char tos[8]       = {'0','1','1','0','0','1','1','0'};
    char flags[3]     = {'0','0','0'};
    int ipSrc[4]      = {192, 168, 100, 200};
    int ipDst[4]      = {192, 168, 1, 1};
    char OC[2]        = {'0', '0'};
    char ON[5]        = {'0', '0', '0', '0', '0'};

    creaDatagramRete(
        pacchettoIp,
        tos,
        1,
        flags,
        0,
        64,
        6,
        ipSrc,
        ipDst,
        3,
        '0',
        OC,
        ON,
        ContenutoFileInputBinario
    );

    string contenutoOutputRete = creaDatagramStringaRete(pacchettoIp);
    ScritturaMessaggio(contenutoOutputRete, NomeFileOutputRete);
	cout<<"Creazione pdu rete completata"<<endl;

    //Livello Fisico
    cout<<"Creazione del pdu fisico..."<<endl;
    Ethernetv2Header frameEthernet;
    int macSrc[6] = {0x00, 0xff, 0x80, 0xac, 0x52, 0xeb};
    int macDst[6] = {0xff, 0x08, 0x00, 0xc2, 0x54, 0x7b};

    creaDatagramFisico(frameEthernet, macSrc, macDst, contenutoOutputRete);
    string contenutoOutputFisico = creaDatagramStringaFisico(frameEthernet);
    ScritturaMessaggio(contenutoOutputFisico, NomeFileOutputFisico);
    cout<<"Creazione del pdu fisico completata"<<endl;
    
    return 0;
    
}

