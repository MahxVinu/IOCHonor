# Introdução

Um script em Python com a capacidade de enriquecer diversos IOCs para analistas de segurança, pode ser utilizando um IOC por comando ou informando uma lista. O script retorna as informações importantes quando consultado, a fim de determinar se é malicioso ou não.

Nesse script foram utilizados 3 fontes diferentes (Virustotal, AbuseIPD, AlienVault OTX) para uma precisão maior na hora da consulta.

# Instalação

Primeiramente, crie e ative um ambiente virtual (procedimento recomendado)

    python -m venv .venv 


Ative-o:

  	.venv\Scripts\activate 

  
Instale as bibliotecas necessárias via pip:

    pip install -r requirements.txt



# Tutorial

para exemplos de utilização da ferramenta clique [aqui](exemplos)