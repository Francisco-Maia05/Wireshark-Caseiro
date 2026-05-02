sequenceDiagram
    participant n1 as PC1 (Sniffer) <br> 10.0.0.20
    participant n2 as PC2 (Alvo) <br> 10.0.0.21

    Note over n1,n2: Início do Ping (Lógica Stateless contornada pelo Sniffer)
    n1->>n2: ICMP Echo Request (Type 8) | ID: 5542 | Seq: 1
    Note right of n2: O PC2 recebe e inverte os IPs
    n2-->>n1: ICMP Echo Reply (Type 0) | ID: 5542 | Seq: 1
    Note left of n1: Sniffer cruza o ID e a Seq<br>para validar que é o "(Reply ao pacote #1)"