%package machine.dongle.script

%scenario Tokenize {
    %define NL          /\r\n|\r|\n/
    %define SP          /[[:space:]]/
    %define HEX         /0[xX][[:xdigit:]]+/
    %define OCT         /0[0-7]+/
    %define NUM         /[0-9]+/
    %define IDEN        /[[:alpha:]][[:alnum:]_]*/

    %state SC_MCOMM, SC_SCOMM

    <INITIAL>{
        %action AC_MCOMM_BEGIN      /\/\*/
        %action AC_SCOMM_BEGIN      /\/\//
        %action AC_NUMBER           /{HEX}|{OCT}|{NUM}/

        %action AC_IF               /if/
        %action AC_ELSE             /else/
        %action AC_FOR              /for/
        %action AC_WHILE            /while/
        %action AC_DO               /do/
        %action AC_CONST            /const/
        %action AC_PUBLIC           /public/

        %action AC_OP_LOGIC_OR      /"||"/
        %action AC_OP_LOGIC_AND     /"&&"/
        %action AC_OP_EQ            /"=="/
        %action AC_OP_NE            /"!="/
        %action AC_OP_LE            /"<="/
        %action AC_OP_GE            /">="/
        %action AC_OP_SHIFT_LEFT    /"<<"/
        %action AC_OP_SHIFT_RIGHT   /">>"/
        %action AC_OP_SHIFT_RIGHT_U /">>>"/

        %action AC_IDEN             /{IDEN}/
        %action AC_NEWLINE          /{NL}/
        %action AC_SPACE            /{SP}/
        %action AC_ANY              /./
    }

    <SC_MCOMM>{
        %action AC_MCOMM_END        /\*\//
        %action AC_MCOMM_NL         /{NL}/
        %action AC_MCOMM_ANY        /./
    }

    <SC_SCOMM>{
        %action AC_SCOMM_END        /{NL}/
        %action AC_SCOMM_ANY        /./
    }
}

