package cmd_soap_msg;

use SOAP::WSDL::Client; # para criar a ligação com o servidor SOAP
use Encode;             # para encode e decode

# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
	return 1;
}

# Função que devolve o cliente de ligação (preprod ou prod) ao servidor SOAP da CMD
sub get_wsdl{

	@wsdl = ('https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl',
	        'https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl');


	my ($input) = @_;
	
	# Verifica se número é 0 ou 1 e se a string tem comprimento 1
	die "Invalid choice!" unless ($input =~ /[01]+/ && length($input) == 1);

	$choice = int($input);
	die 'Invalid choice!' unless ($choice == 0 or $choice == 1);

	my $soap = SOAP::WSDL::Client->new({
    	proxy => $wsdl[choice]
   		});

	return $soap;
}


# Devolve a hash acrescentada do prefixo do tipo de hash utilizada
sub hashPrefix{
	return 1;
}

# GetCertificate(applicationId: xsd:base64Binary, userId: xsd:string)
sub  getcertificate{

	# Só aceitamos nesta função 2 argumentos
	$number_of_args = scalar(@_);
	print "passed args = @_\n";
	print "$number_of_args\n";
	die "U can't pass more than 2 variables!!" unless $number_of_args == 2;

	#obter a applicationId e o userId dos argumentos passados
	my ($choice,$appId,$userId) = @_;

	# Verificar se ambos os parâmetros são números
	#EXEMPLO:
	#if ( ($var ne "0") && ($var == 0))
  	#{ # $var is a number
  	#}
	# Verifica se todas as strings inseridas são números naturais e não têm caracters estranhos
	die "Only numbers are accepted!!" unless (($appId =~ /^\d+$/) && ($userId =~ /^\d+$/));

	#Criação de um dicionário para teste
	$encodedAppId = encode('UTF-8',$appId);
	%data = ('applicationId' => $encodedAppId , 'userId' => $userId);

	$soap = get_wsdl($choice);

	#Obtenção do certificado
	return $soap->call('GetCertificate',$data);
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