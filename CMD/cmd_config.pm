package cmd_config;

#Ficheiro de configuração do URL do WSDL a utilizar e da APPLICATION_ID fornecida pela AMA.


# ApplicationId da entidade, fornecida pela AMA
$APPLICATION_ID = 'b826359c-06f8-425e-8ec3-50a97a418916';

#Devolve APPLICATION_ID (fornecida pela AMA).
sub get_appid{
	return $APPLICATION_ID;
}

1;