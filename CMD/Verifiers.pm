package verifiers;

sub sqlInjection{
	my $argument = $_[0];
	return 0 if(! defined $argument);
	#print("SEARCHING FOR SQL INJECTIONS ON $argument\n");
	@array_sql_expressions = ('SELECT',' \* ','FROM','DELETE','CREATE','TRANSACTION','BEGIN','USING','ON','AND','NOT','MATCHED','THEN','UPDATE','MERGE','INTO','SET','INSERT','WHERE','\"','DROP','END');
	map {return 1 if ($argument =~ /$_/);} @array_sql_expressions;
	return 0;
}

sub xmlInjection{
	my $argument = $_[0];
	return 0 if(! defined $argument);
	#print("SEARCHING FOR XML INJECTIONS ON $argument\n");
	# Se o input tiver este padrão <qualquer coisa> ... </qualquer coisa> asssumimos ser xml!!
    return 1 if ($argument =~ /<[a-zA-Z]*(>[^(<\/)]*<\/[a-zA-Z]*|\/)?>/);
    return 0;
}

#[1]  -f      -> ficheiro (verificar tamanho & não tem | para fazer pipeline)
#[2]  -u      -> número de utilizador (apenas números - indicativo espaço e 9 digitos)
#[3]  -p      -> pin (número de tamanho 4)
#[4]  -otp    -> input line code received on selfphone (VAZIO/apenas digitos)
#[5]  -procId -> Process Id (VAZIO/numeros)
#[7]  -prod   -> escolher prepod ou pod {0,1}

sub input{
	my @args = @{$_[0]};
	
	if(defined $args[1]){
		#print("A testar file!$args[1]\n");
		#Verificação da correção do nome/caminho do ficheiro alvo -> serve para impedir pipelining e ficheiros com nomes errados
		# WHITE LIST
		die "(White List) Do not try to pipeline or use any strange character on the file to be read...\n" unless $args[1] =~ /^[a-zA-Z\.\/\-\%\&\+\*\(\)\{\}\[\]0-9\?\'<>áàãâäéèêëíìïóòôõöùúûüçñÁÀÃÂÄÉÈÊËÍÌÎÏÓÒÕÔÖÚÙÛÜCÑ ]+$/;
		# BLACK LIST -> sere para o caso em que não se fornece argumento e a string é o nome da opção seguinte
		die "(Black List) Do not try to pipeline or use any strange character on the file to be read..." unless $args[1] !~ /^(-)?[(u)(p)(otp)(procId)(app)(prod)(d)]{1}$/;
		#die "(Black List) Do not try to pipeline or use any strange character on the file to be read..." unless $args[1] !~ /[\|;,'?!"\\]/;	
	}
	if(defined $args[2]){
		#print("a testar phone number!\n");
		#Verificação de números internacionais com indicativo do pais e número
		#die "Wrong Phone Number!! The notation is: +XXX NNNNNNNNN\n" unless $args[2] =~ /^\+[0-9]{1,3} [0-9]{4,14}$/;	
		#Verificação de números nacionais com indicativo do pais e número
		die "Wrong Phone Number!! The notation is: +XXX NNNNNNNNN\n" unless $args[2] =~ /^\+351 [0-9]{9}$/;	
	
	}
	if(defined $args[3]){
		#print("a testar pin!\n");
		#Verificação do pin
		die "Wrong Pin!! The notation is: XXXX\n" unless $args[3] =~ /^[0-9]{4}$/;		
	}
	if(defined $args[4]){
		#print("a testar OTP!\n");
		die "Wrong OTP!! The notation is: XXXX\n" unless $args[4] =~ /^[0-9]{4}$/;
		
	}
}

sub valid_otp{
	my $argument = $_[0];
	if(defined($argument)){
		die "Wrong OTP!! The notation is: XXXXXX\n" unless $argument =~ /^[0-9]{6}$/;
	}
	else{
		die "OTP not defined!\n"
	}
}

1;