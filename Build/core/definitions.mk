

# -----------------------------------------------------------------------------
# Macro    : empty
# Returns  : an empty macro
# Usage    : $(empty)
# -----------------------------------------------------------------------------
empty :=

# -----------------------------------------------------------------------------
# Macro    : space
# Returns  : a single space
# Usage    : $(space)
# -----------------------------------------------------------------------------
space  := $(empty) $(empty)
space2 := $(space) $(space)
space4 := $(space) $(space) $(space) $(space)

# -----------------------------------------------------------------------------
# Macro    : hide
# Returns  : nothing
# Usage    : $(hide)<make commands>
# -----------------------------------------------------------------------------
ifeq ($(V),1)
hide = $(empty)
else
hide = @
endif

# -----------------------------------------------------------------------------
# Macro    : my-dir
# Returns  : the directory of the current Makefile
# Usage    : $(my-dir)
# -----------------------------------------------------------------------------
my-dir = $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

# -----------------------------------------------------------------------------
# Macro     : n-dir
# Arguments : 1) file path ( ex : a/b/c/d.e )
# Returns   : the directory of the file ( ex : a/b/c )
# -----------------------------------------------------------------------------
n-dir = $(patsubst %/,%,$(dir $1))

# -----------------------------------------------------------------------------
# Macro    : local-makefile
# Returns  : the name of the last parsed xModule.mk file
# Usage    : $(local-makefile)
# -----------------------------------------------------------------------------
local-makefile = $(lastword $(filter %xModule.mk,$(MAKEFILE_LIST)))

# ----------------------------------------------------------------------------
# Function:  last
# Arguments: 1: A list
# Returns:   Returns the last element of a list
# ----------------------------------------------------------------------------
last = $(word $(words $1), $1)

# -----------------------------------------------------------------------------
# Function : last2
# Arguments: a list
# Returns  : the penultimate (next-to-last) element of a list
# Usage    : $(call last2, <LIST>)
# -----------------------------------------------------------------------------
last2 = $(word $(words $1), x $1)


# -----------------------------------------------------------------------------
# Function : last3
# Arguments: a list
# Returns  : the antepenultimate (second-next-to-last) element of a list
# Usage    : $(call last3, <LIST>)
# -----------------------------------------------------------------------------
last3 = $(word $(words $1), x x $1)


# -----------------------------------------------------------------------------
# Macro    : this-makefile
# Returns  : the name of the current Makefile in the inclusion stack
# Usage    : $(this-makefile)
# -----------------------------------------------------------------------------
this-makefile = $(lastword $(MAKEFILE_LIST))


# -----------------------------------------------------------------------------
# Function : assert-defined
# Arguments: 1: list of variable names
# Returns  : None
# Usage    : $(call assert-defined, VAR1 VAR2 VAR3...)
# Rationale: Checks that all variables listed in $1 are defined, or abort the
#            build
# -----------------------------------------------------------------------------
assert-defined = $(foreach __varname,$(strip $1),\
  $(if $(strip $($(__varname))),,\
    $(call error, Assertion failure: $(__varname) is not defined)\
  )\
)

# -----------------------------------------------------------------------------
# Function : clear-vars
# Arguments: 1: list of variable names
#            2: file where the variable should be defined
# Returns  : None
# Usage    : $(call clear-vars, VAR1 VAR2 VAR3...)
# Rationale: Clears/undefines all variables in argument list
# -----------------------------------------------------------------------------
clear-vars = $(foreach __varname,$1,$(eval $(__varname) := $(empty)))

# ----------------------------------------------------------------------------
# Function:  set_create
# Arguments: 1: A list of set elements
# Returns:   Returns the newly created set
# ----------------------------------------------------------------------------
set_create = $(sort $1)

# ----------------------------------------------------------------------------
# Function:  set_insert
# Arguments: 1: A single element to add to a set
#            2: A set
# Returns:   Returns the set with the element added
# ----------------------------------------------------------------------------
set_insert = $(sort $1 $2)

# ----------------------------------------------------------------------------
# Function:  set_remove
# Arguments: 1: A single element to remove from a set
#            2: A set
# Returns:   Returns the set with the element removed
# ----------------------------------------------------------------------------
set_remove = $(filter-out $1,$2)

# ----------------------------------------------------------------------------
# Function: file_base_name
# Arguments: 1: A file pathname list ( ex : a/b/foo.c c/d/bar.s)
# Returns: file basename list        ( ex : foo bar )
# ----------------------------------------------------------------------------
file_base_name = $(call basename,$(call notdir,$1))

##
##
##
__x4c_local_variant := $(call set_create,)

# ----------------------------------------------------------------------------
# Function: x4c_register_local_variant
# Arguments: 1: New variant name
# ----------------------------------------------------------------------------
x4c_register_local_variant = \
  $(if $(call filter,$(__x4c_local_variant),$1),  \
	   $(call error,Local variant ** $1 ** already defined.)) \
	$(eval __x4c_local_variant := $(call set_insert,$1,$(__x4c_local_variant)))
