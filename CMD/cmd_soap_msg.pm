package cmd_soap_msg;

# preparation
use SOAP::Lite;
use SOAP::WSDL;
use XML::Compile::WSDL11;      # use WSDL version 1.1
use XML::Compile::SOAP11;      # use SOAP version 1.1
use XML::Compile::Transport::SOAPHTTP;
use Encode;             # para encode e decode

# you want some trace?
use Log::Report mode => 'DEBUG';


# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
	return 1;
}

# Função que devolve o cliente de ligação (preprod ou prod) ao servidor SOAP da CMD
sub get_wsdl{

	@wsdl = ('https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl',
	        'https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl');


	my ($input) = @_[0];

	# não há necessidade de testar o prod por este ser 0 ou 1 sempre 
	# garantido pelo Getopt ao fazer o parsing do @ARGV


	$choice = int($input);
 

	return $wsdl[$choice]
}


# Devolve a hash acrescentada do prefixo do tipo de hash utilizada
sub hashPrefix{
	return 1;
}

# GetCertificate(applicationId: xsd:base64Binary, userId: xsd:string)
sub  getcertificate{

	# Só aceitamos nesta função 2 argumentos
	$number_of_args = scalar(@_);

	#Obter a escolha do WSDL
	my $res = @_[0];
	#obter a applicationId e o userId dos argumentos passados
	my $appId  = $_[1][6];
	my $userId = $_[1][2];

	# Verifica se todas as strings inseridas são números naturais e não têm caracters estranhos
	die "Only numbers are accepted!!" unless ($appId =~ /^\d+$/ && $userId =~ /\+\d+/);

	#Criação de um dicionário para teste
	$encodedAppId = encode('UTF-8',$appId);
	%data = ('applicationId' => $encodedAppId , 'userId' => $userId);
	#método a ser usado
	$method = "GetCertificate";

	#Criação do cliente
	#Tentativa 1
	#my $wsdl = SOAP::Lite->new(uri => 'urn:$method' ,proxy => $res);
	#my $answer = $wsdl->call(%data);
	#my $answer2 = $wsdl->call($method,%data)->result();
	#print "answer = $answer2\n";
	
	#Tentativa 2
	#my $soap = SOAP::WSDL->new(uri => 'http://schemas.xmlsoap.org/wsdl/',wsdl => $res);
	#my $answer = $soap->call($method, %data);
	#print "answer = $answer";
	
	#Tentativa 3
	#my $client = SOAP::Lite->new()
	#$client->service($res);
	#my $result = $soap->call($method, %data);
	#return $answer

	#Tentativa 4
	$server =  SOAP::Lite->new(proxy => $res);
	$answer = $server -> call($method,%data) -> result;
	print "res = $res\n";
	return $answer
}



# CCMovelSign(request: ns2:SignRequest) -> CCMovelSignResult: ns2:SignStatus
# ns2:SignRequest(ApplicationId: xsd:base64Binary, DocName: xsd:string,
#                  Hash: xsd:base64Binary, Pin: xsd:string, UserId: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                   Message: xsd:string, ProcessId: xsd:string)
sub ccmovelsign{
	return 1;
}


# CCMovelMultipleSign(request: ns2:MultipleSignRequest,
#                              documents: ns2:ArrayOfHashStructure)
#                                  -> CCMovelMultipleSignResult: ns2:SignStatus
# ns2:MultipleSignRequest(ApplicationId: xsd:base64Binary, Pin: xsd:string,
#                                                           UserId: xsd:string)
# ns2:ArrayOfHashStructure(HashStructure: ns2:HashStructure[])
# ns2:HashStructure(Hash: xsd:base64Binary, Name: xsd:string, id: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                   Message: xsd:string, ProcessId: xsd:string)
sub ccmovelmultiplesign{
	return 1;
}

# ValidateOtp(code: xsd:string, processId: xsd:string, applicationId:
#                      xsd:base64Binary) -> ValidateOtpResult: ns2:SignResponse
# ns2:SignResponse(ArrayOfHashStructure: ns2:ArrayOfHashStructure,
#                          Signature: xsd:base64Binary, Status: ns2:SignStatus)
# ns2:ArrayOfHashStructure(HashStructure: ns2:HashStructure[])
# ns2:HashStructure(Hash: xsd:base64Binary, Name: xsd:string, id: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                                   Message: xsd:string, ProcessId: xsd:string)
sub validate_otp{
	return 1;
}


# este parâmetro tem de existir por sintaxe do perl
1;