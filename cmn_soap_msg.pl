
package cmd_soap_msg;

use SOAP::WSDL::Client; # para criar a ligação com o servidor SOAP
 use Encode;            # para encode e decode

 
sub get_wsdl{

	@wsdl = ('https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl',
	        'https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl')	


	my ($input) = @_;

	# Verifica se número é válido (0 ou 1)
	$choice = int($input)
	die 'Invalid choice!' unless ($choice == 0 or $choice == 1)

	my $soap = SOAP::WSDL::Client->new({
    	proxy => $wsdl[choice]
   		});

	return $soap
}

# GetCertificate(applicationId: xsd:base64Binary, userId: xsd:string)
sub  GetCertificate{

	# Só aceitamos nesta função 2 argumentos
	$number_of_args = scalar(@_);
	die "U can't pass more than 2 variables!!" unless $number_of_args == 2;

	#obter a applicationId e o userId dos argumentos passados
	my ($choice,$appId,$userId) = @_;

	# Verificar se ambos os parâmetros são números
	#EXEMPLO:
	#if ( ($var ne "0") && ($var == 0))
  	#{ # $var is a number
  	#}
	# Verifica se todas as strings inseridas são números naturais e não têm caracters estranhos
	die "Only numbers are accepted!!" unless (($choice =~ /^\d+$/) && ($appId =~ /^\d+$/) && ($userId =~ /^\d+$/))

	#Criação de um dicionário para teste
	$encodedAppId = encode('UTF-8',$appId)
	%data = ('applicationId' => $encodedAppId , 'userId' => $userId)

	$soap = get_wsdl($choice)

	#Obtenção do certificado
	$soap->call('GetCertificate',$data)
}