#
# Name:		Make Test Files From CSV Files
# Version:	0.2
# Date:		August 6, 2022
# Author:	Brian O'Hagan
# Email:	brian199@comcast.net
# Legal Notice:	(c) Copyright 2020 by Brian O'Hagan
#		Released under the Apache v2.0 license. I would appreciate a copy of any modifications
#		made to this package for possible incorporation in a future release.
#

#
# Convert test case file into test files
#
proc process_config_file {filename} {
    set prev ""
    set test 0

    # Open file with test case indo    
    set in [open $filename r]
    array set cases [list]

    # Open output test file
    set out [open [format %s.test [file rootname $filename]] w]
    array set cases [list]
    
    # Add setup commands to test file
    puts $out [format "# Auto generated test cases for %s" [file tail $filename]]
    #puts $out [format "# Auto generated test cases for %s created on %s" [file tail $filename] [clock format [clock seconds]]]
    
    # Package requires
    puts $out "\n# Load Tcl Test package"
    puts $out [subst -nocommands {if {[lsearch [namespace children] ::tcltest] == -1} {\n\tpackage require tcltest\n\tnamespace import ::tcltest::*\n}\n}]
    puts $out {set auto_path [concat [list [file dirname [file dirname [info script]]]] $auto_path]}
    puts $out ""
    
    # Generate test cases and add to test file
    while {[gets $in data] > -1} {
	# Skip comments
	set data [string trim $data]
	if {[string match "#*" $data]} continue

	# Split comma separated fields with quotes
	set list [list]
	while {[string length $data] > 0} {
	    if {[string index $data 0] eq "\""} {
		# Quoted
		set end [string first "\"," $data]
		if {$end == -1} {set end [expr {[string length $data]+1}]}
		lappend list [string map [list {""} \"] [string range $data 1 [incr end -1]]]
		set data [string range $data [incr end 3] end]
		
	    } else {
		# Not quoted, so no embedded NL, quotes, or commas
		set index [string first "," $data]
		if {$index == -1} {set index [expr {[string length $data]+1}]}
		lappend list [string range $data 0 [incr index -1]]
		set data [string range $data [incr index 2] end]
	    }
	}

	# Get command or test case
	foreach {group name constraints setup body cleanup match result output errorOutput returnCodes} $list {
	    if {$group eq "command"} {
		# Pass-through command
		puts $out $name

	    } elseif {$group ne "" && $body ne ""} {
		set group [string map [list " " "_"] $group]
		if {$group ne $prev} {
		    incr test
		    set prev $group
		    puts $out ""
		}

		# Test case
		set buffer [format "\ntest %s-%d.%d {%s}" $group $test [incr cases($group)] $name]
		foreach opt [list -constraints -setup -body -cleanup -match -result -output -errorOutput -returnCodes] {
		    set cmd [string trim [set [string trimleft $opt "-"]]]
		    if {$cmd ne ""} {
			if {$opt in [list -setup -body -cleanup]} {
			    append buffer " " $opt " \{\n"
			    foreach line [split $cmd ";"] {
				append buffer \t [string trim $line] \n
			    }
			    append buffer "    \}"
			} elseif {$opt in [list -output -errorOutput]} {
			    append buffer " " $opt " {" $cmd \n "}"
			} elseif {$opt in [list -result]} {
			    if {[string index $cmd 0] in [list \[ \" \{]} {
				append buffer " " $opt " " $cmd
			    } elseif {[string match {*[\\$]*} $cmd]} {
				append buffer " " $opt " \"" [string map [list \\\\\" \\\"] [string map [list \" \\\" ] $cmd]] "\""
			    } else {
				append buffer " " $opt " {" $cmd "}"
			    }
			} else {
			    append buffer " " $opt " {" $cmd "}"
			}
		    }
		}
		puts $out $buffer

	    } else {
		# Empty line
		puts $out ""
	    }
	    break
	}
    }

    # Output clean-up commands
    puts $out "\n# Cleanup\n::tcltest::cleanupTests\nreturn"
    close $out
    close $in
}

#
# Call script
#
foreach file [glob *.csv] {
    process_config_file $file
}
exit
