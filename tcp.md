sequenceDiagram
    participant n1 as Cliente (n1) <br> Porta Aleatória (Ex: 45012)
    participant n2 as Servidor Web (n2) <br> Porta 80

    Note over n1,n2: 1. 3-Way Handshake (Estabelecimento)
    n1->>n2: TCP [SYN] (S)
    n2-->>n1: TCP [SYN, ACK] (S,A)
    n1->>n2: TCP [ACK] (A)
    
    Note over n1,n2: 2. Transferência de Dados (Nível de Aplicação)
    n1->>n2: HTTP GET / (TCP [PSH, ACK])
    n2-->>n1: HTTP 200 OK (Dados da Página) (TCP [PSH, ACK])
    
    Note over n1,n2: 3. Teardown (Encerramento da Ligação)
    n1->>n2: TCP [FIN, ACK] (F,A)
    n2-->>n1: TCP [FIN, ACK] (F,A)
    n1->>n2: TCP [ACK] (A)