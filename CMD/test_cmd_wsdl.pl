use File::Basename;
use Crypt::X509;
use Crypt::OpenSSL::RSA;
use File::Slurp;
use Try::Tiny;
use Digest::SHA qw(sha256);
use MIME::Base64;
use Getopt::Long;
use Switch;

use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . "/CMD/";
use cmd_config;
use cmd_soap_msg;

$TEXT = "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)";
$VERSION = "version: 1.0";
$APPLICATION_ID = cmd_config::get_appid();

#Função main do programa.
#Verifica se o APPLICATION_ID é um número natural (inteiro positivo)
die "Configure o APPLICATION_ID" unless $APPLICATION_ID =~ /^\d+$/;

#Verificação de um número de inputs suficiente
$number_of_args = $#ARGV + 1;
die "Use -h for usage:\n  $0, -h for all operations\n  $0, <oper1> -h for usage of operation <oper1>\n" unless $number_of_args > 1;

#Faz o parser dos argumentos recebidos
@args = &args_parse;
print "args = @args\n";

die "Argumento passado (prod) deve ser 0 ou 1 não indefinido." unless defined($args[5]);
$client = cmd_soap_msg::get_wsdl($args[5]);

switch($args[0]) {
    case "test"    { print testall($client,$args);                           }
    case "gc"      { print cmd_soap_msg::getcertificate($client,$args);      }
    case "ms"      { print cmd_soap_msg::ccmovelsign($client,$args);         }
    case "mms"     { print cmd_soap_msg::ccmovelmultiplesign($client,$args); }
    case "otp"     { print cmd_soap_msg::validate_otp($client,$args);        }
    else           { die "Select a proper Option!!" ;                        }
}


# -h    -> ajuda
# -o    -> opção escolhida (test, getcertificat,...)
# -f    -> nome do ficheiro
# -u    -> número do utilizador (ex:+351 000000000)
# -p    -> pin
# -otp  -> processId
# -prod -> escolher prepod ou pod {0,1}
# -d    -> permite debug {0,1}
sub args_parse{
    my @args;
    GetOptions(
        'h'     => \( my $help = 0),
        'o:s'    => \$args[0],
        'f:s'    => \$args[1],
        'u=s'    => \$args[2],
        'p:s'    => \$args[3],
        'otp:s'  => \$args[4],
        'procId' => \$args[5],
        'app:s'  => \$args[6],
        'prod:i' => \($args[7] = 0), #default value is 0 -> usa prepod
        'd:i'    => \($args[8] = 0), #default value is 0 -> sem debug
    );
    if(help == 1){
        switch($args[0]){
            case "test"    { print "Automatically test all commands\n";  info(@a = ('-f','-u','-p')); }
            case "gc"      { print "Get user certificate\n";             info(@a = ('-u')); }
            case "ms"      { print "Start signature process\n";          info(@a = ('-u','-p')); }
            case "mms"     { print "Start multiple signature process\n"; info(@a = ('-u','-p')); }
            case "otp"     { print "Validate OTP\n";                     info(@a = ('-otp','-procId')); }
            else           { die "Select a proper Option!!" ;                    }
        }

    }
    return @args;
}

sub info{
    my %help = (
        '-h'      => 'help',
        '-f'      => 'filepath',
        '-u'      => 'user phone number ( -u +XXX NNNNNNNNN)',
        '-p'      => 'CMD signature PIN',
        '-otp'    => 'OTP received in your device',
        '-procId' => 'ProcessID received in the answer of the CCMovelSign/CCMovelMultipleSign command',
        '-app'    => 'CMD ApplicationId (-app XXXXX)',
        '-prod'   => 'Use production SCMD service (preproduction SCMD service used by default)',
        '-d'      => 'show debug information'
        );
    print "\nPositional Arguments:\n";
    map { print "$_    => $help{$_}\n"; } @_ ;
    print "\nOptional Arguments:\n";
    map { print "$_    => $help{$_}\n"; } (@Array = ('-h','-app','-prod','-d')) ;
    exit 1;
}
# Testa todos os comandos
sub testall{
    print "$TEXT \n  $VERSION\n";
    print "\n+++ Test All inicializado +++\n";
    print " 0% ... Leitura de argumentos da linha de comando - file: $args.file user: $args.user pin: $args.pin\n";
    print "10% ... A contactar servidor SOAP CMD para operação GetCertificate\n";
    my ($client, $args) = @_;
    $cmd_certs = cmd_soap_msg::getcertificate($client, @args);
    if (not defined($cmd_certs)){
        die "Impossível obter certificado";
    }
    $decoded = Crypt::X509->new(cert => $cmd_certs);
    if ($decoded->notBefore < time()) {
        die "Certificate: not yet valid!";
    }
    if ($decoded->not_after < time()) {
        die "Certificate: invalid expiration time!";
    }
    %certs_chain = ("user" => $decoded->Subject, "ca" => $decoded->Issuer, "root" => $decoded->authorityCertIssuer);
    print "20% ... Certificado emitido para $certs_chain[\"user\"] pela Entidade de Certificação certs_chain[\"ca\"] na hierarquia do certs_chain[\"root\"]";
    print "30% ... Leitura do ficheiro $args.file";
    try{
        my $file_content = read_file(args->file);
    } catch{
        die "Ficheiro não encontrado.";
    }
    print "40% ... Geração de hash do ficheiro $args.file";

    $args->hash = sha256($file_content); # Geração do Digest
    $decoded_arg = decode_base64(encode_base64($args->hash));
    print "50% ... Hash gerada (em base64): $decoded_arg";
    print "60% ... A contactar servidor SOAP CMD para operação CCMovelSign";
    $args->docName = args->file;
    #res["Code"] == res[0]
    #res["ProcessId"] == res[1]
    @res = cmd_soap_msg::ccmovelsign($client, $args);

    if ($res[0] != "200"){
        die "Erro $res[0]. Valide o PIN introduzido.";
    }
    print "70% ... ProcessID devolvido pela operação CCMovelSign: $res[1]";
    $args->ProcessId = @res[1];
    print "80% ... A iniciar operação ValidateOtp";
    print "Introduza o OTP recebido no seu dispositivo: ";
    $opt = <STDIN>;
    # Removes new line from the input 
    chomp $opt; 
    $args->OPT = $opt;
    print "90% ... A contactar servidor SOAP CMD para operação ValidateOtp";
    #validate_res["Status"]["Code"] == validate_res[0][0]
    #validate_res["Status"]["Message"] == validate_res[0][1]
    #validate_res["Signature"] == validate_res[1]
    @validate_res = cmd_soap_msg::validate_otp($client, $args);
    if($validate_res[0][0] != "200"){
        die "Erro $validate_res[0][0]. $validate_res[0][1]";
    }
    $decoded_res = decode_base64(encode_base64($validate_res[1]));
    print "100% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: $decoded_res";
    print "110% ... A validar assinatura ...";
    $digest = sha256($file_content);
    my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($decoded->pubkey);
    my $valid = $rsa_pub->do_verify($digest, $validate_res[1]);
    assert($valid,"Signature Verification!");
    print "Assinatura verificada com sucesso, baseada na assinatura recebida, na hash gerada e na chave pública do certificado de @certs_chain[\"user\"]";
    return "\n+++ Test All finalizado +++\n";
}