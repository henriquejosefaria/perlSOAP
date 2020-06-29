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
use verifyers;

$TEXT = "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)";
$VERSION = "version: 1.0";
$APPLICATION_ID = cmd_config::get_appid();

#Função main do programa.
#Verifica se o APPLICATION_ID é um número natural (inteiro positivo)
die "Configure o APPLICATION_ID\n" unless defined $APPLICATION_ID;

#Verificação de um número de inputs suficiente
$number_of_args = $#ARGV + 1;
die "Use -h for usage:\n  $0, -h for all operations\n  $0, <oper1> -h for usage of operation <oper1>\n" unless $number_of_args > 1;

#Faz o parser dos argumentos recebidos
@args = &args_parse;

die "Argumento passado (prod) deve ser 0 ou 1 não indefinido.\n" unless defined($args[7]);
$client = cmd_soap_msg::get_wsdl($args[5]);

cmd_soap_msg::debug($args[8]);


switch($args[0]) {
    case "test"    { print testall($client,$args);                           }
    case "gc"      { print cmd_soap_msg::getcertificate($client,$args);      }
    case "ms"      { print cmd_soap_msg::ccmovelsign($client,$args);         }
    case "mms"     { print cmd_soap_msg::ccmovelmultiplesign($client,$args); }
    case "otp"     { print cmd_soap_msg::validate_otp($client,$args);        }
    else           { die "Select a proper Option!!\n" ;                        }
}


# -h      -> ajuda
# -o      -> opção escolhida (test, getcertificat,...)
# -f      -> nome do ficheiro
# -u      -> número do utilizador (ex:+351 000000000)
# -p      -> pin
# -otp    -> input line code received on selfphone
# -procId -> Process Id
# -app    -> APPLICATION_ID
# -prod   -> escolher prepod ou pod {0,1}
# -d      -> permite debug {0,1}
# hash    -> hash a ser produzido mais á frente
# docName -> nome a ser copiado do ficheiro
sub args_parse{
    # VERIFICAR TAMANHO DO INPUT, O PERL PERMITE CRESCIMENTO ATÉ AO FIM DA STACK DA RAM
    my @args;
    GetOptions(
        'h'     => \( my $help = 0),
        'o:s'    => \$args[0],
        'f:s'    => \$args[1],
        'u=s'    => \$args[2],
        'p:s'    => \$args[3],
        'otp:s'  => \$args[4],
        'procId' => \$args[5],
        'app:s'  => \($args[6] = $APPLICATION_ID), #default está definido no modulo cmd_config
        'prod'   => \($args[7] = 0), #default value is 0 -> usa prepod
        'd'      => \($args[8] = 0), #default value is 0 -> sem debug
    );

    if(help == 1){
        switch($args[0]){
            case "test"    { print "Automatically test all commands\n";  info(@a = ('-f','-u','-p')); }
            case "gc"      { print "Get user certificate\n";             info(@a = ('-u')); }
            case "ms"      { print "Start signature process\n";          info(@a = ('-u','-p')); }
            case "mms"     { print "Start multiple signature process\n"; info(@a = ('-u','-p')); }
            case "otp"     { print "Validate OTP\n";                     info(@a = ('-otp','-procId')); }
            else           { die "Select a proper Option!!\n" ;          }
        }

    }
    verifyer(\@args);
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

#Verifica tamanho máximo dos inputs e os tipos
#Verifica sql injection
sub verifyer{
    my @args = @{$_[0]};

    verifyers::input(\@args);
    map{die "I know what your up to! Don't try to SQL inject me!!\n" unless verifyers::sqlInjection($_) == 0;} @args;
    map{die "I know what your up to! Don't try to XML inject me!!\n" unless verifyers::xmlInjection($_) == 0;} @args;
    #map{verifyers::} @args;
    #map{verifyers::} @args;
    #map{verifyers::} @args;
    #map{verifyers::} @args;
    #map{verifyers::} @args;

}

# Testa todos os comandos
sub testall{
    print "$TEXT \n  $VERSION\n";
    print "\n+++ Test All inicializado +++\n";
    print " 0% ... Leitura de argumentos da linha de comando - file: $args.file user: $args.user pin: $args.pin\n";
    print "10% ... A contactar servidor SOAP CMD para operação GetCertificate\n";
    my ($client, $args) = @_;
    print("@args");
    $cmd_certs = cmd_soap_msg::getcertificate($client, \@args);
    print "\n\n\n$cmd_certs\n\n\n";
    if (not defined($cmd_certs)){
        die "Impossível obter certificado\n";
    }
    $decoded = Crypt::X509->new(cert => $cmd_certs);
    if ($decoded->notBefore < time()) {
        die "Certificate: not yet valid!\n";
    }
    if ($decoded->not_after < time()) {
        die "Certificate: invalid expiration time!\n";
    }
    %certs_chain = ("user" => $decoded->Subject, "ca" => $decoded->Issuer, "root" => $decoded->authorityCertIssuer);
    print "20% ... Certificado emitido para $certs_chain[\"user\"] pela Entidade de Certificação certs_chain[\"ca\"] na hierarquia do certs_chain[\"root\"]";
    print "30% ... Leitura do ficheiro $args.file";
    try{
        open(my $file_content, "<", $args[1]) or die "Ficheiro não encontrado.\n"; # previne pipelining
        #my $file_content = read_file(args->file);
    } catch{
        die "Ficheiro não encontrado.\n";
    }
    print "40% ... Geração de hash do ficheiro $args.file";

    $args[9] = sha256($file_content); # Geração do Digest
    $decoded_arg = decode_base64(encode_base64($args[9]));
    print "50% ... Hash gerada (em base64): $decoded_arg";
    print "60% ... A contactar servidor SOAP CMD para operação CCMovelSign";
    $args[10] = $args[1];
    #res["Code"] == res[0]
    #res["ProcessId"] == res[1]
    @res = cmd_soap_msg::ccmovelsign($client, $args, "SHA256");

    if ($res[0] != "200"){
        die "Erro $res[0]. Valide o PIN introduzido.\n";
    }
    print "70% ... ProcessID devolvido pela operação CCMovelSign: $res[1]";
    $args[5] = @res[1];
    print "80% ... A iniciar operação ValidateOtp";
    print "Introduza o OTP recebido no seu dispositivo: ";
    $opt = <STDIN>;
    # Removes new line from the input 
    chomp $opt; 
    $args[4] = $opt;
    print "90% ... A contactar servidor SOAP CMD para operação ValidateOtp";
    #validate_res["Status"]["Code"] == validate_res[0][0]
    #validate_res["Status"]["Message"] == validate_res[0][1]
    #validate_res["Signature"] == validate_res[1]
    @validate_res = cmd_soap_msg::validate_otp($client, $args);
    if($validate_res[0][0] != "200"){
        die "Erro $validate_res[0][0]. $validate_res[0][1]\n";
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