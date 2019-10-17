Questa repository, creata per il progetto di SDN del Politecnico di Milano, implementa una funzione di load balancini sfruttando il framework Ryu. 

File della repository:
- Controller.py contiene il codice definitivo del controllore lanciabile con ryu.
- controller_LAB.py è la versione del controllore leggermente modificare in modo da funzionare sull'architettura fisica del laboratorio.
- mininetTOP.py contiene la topologia su cui far girare il controllore. Tuttavia le topologie utilizzabili sono molteplici, l'unico vincolo è che lo switch su cui viene effettuato il load balancing riceva i pacchetti da un unico ingresso.
- Strutture pacchetti ryu.txt contiene delle informazioni utili sul framework ryu.


