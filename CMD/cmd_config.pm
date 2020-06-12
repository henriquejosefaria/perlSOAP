package cmd_config;

#Ficheiro de configuração do URL do WSDL a utilizar e da APPLICATION_ID fornecida pela AMA.


# ApplicationId da entidade, fornecida pela AMA
$APPLICATION_ID = 'Change to your ApplicationId';

#Devolve APPLICATION_ID (fornecida pela AMA).
sub get_appid{
	return $APPLICATION_ID;
}