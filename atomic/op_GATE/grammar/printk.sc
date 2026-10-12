%package machine.grammar.matrix

/**
 *!
 */
%scenario Printk {
    %define FLAGs		/[0\+\-\#\x20]/
    %define SIZE1		/(hh)/
    %define SIZE2		/(h)/
    %define SIZE4		/(l|z|t)/
    %define SIZE8		/(ll|j)/

    %state xFMT_START, xFMT_WIDTH, xFMT_PREC 

    <INITIAL>{
        %action xACT_PERCENT    /"%%"/
        %action xACT_START      /"%"/
        %action xACT_ECHO       /([^%]|\r|\n)+/
    }

    <xFMT_START>{
        %action xACT_FLAGs_Z    /{FLAGs}+/
        %action xACT_WIDTH_N    /{FLAGs}*[1-9][0-9]*/
        %action xACT_WIDTH_READ /{FLAGs}*\*/
    }

    <xFMT_START,xFMT_WIDTH>{
        %action xACT_PREC_READ  /\.\*/
        %action xACT_PREC_0     /\./
        %action xACT_PREC_N     /\.[0-9]+/
    }

    <xFMT_START,xFMT_WIDTH,xFMT_PREC>{
        %action xACT_WRCN       /n/
        %action xACT_STRV       /s/
        %action xACT_CHAR       /c/
        %action xACT_PONT       /p/
        %action xACT_INT1       /{SIZE1}[diuxXo]/
        %action xACT_INT2       /{SIZE2}[diuxXo]/
        %action xACT_INT4       /{SIZE4}?[diuxXo]/
        %action xACT_INT8       /{SIZE8}[diuxXo]/
        %action xACT_REAL8      /l?[fFeEgGaA]/
        %action xACT_REAL16     /L[fFeEgGaA]/
    }
}
