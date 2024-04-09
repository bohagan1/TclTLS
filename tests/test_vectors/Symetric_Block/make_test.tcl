#
# Test Vectors
#

#
# Get string or hex string value
#
proc get_value {type data {count 1}} {
    # Handle hex string
    if {$type eq "s" && [string length $data] > 0 && [string index $data 0] ne "\""} {
	set data [format {[binary decode hex %s]} $data]
    }
    if {$type eq "s" && $count > 1} {
	set data [format {[string repeat %s %d]} $data $count]
    }
    return $data
}

#
# Create test case and output to test file
#
proc do_test {group cipher test_num tc params fn} {
    array set config [list iterations 1 repeat 1]
    array set config $params

    # Test info
    set line [format "tcltest::test %s-%d.%d {%s %s} \\\n\t" $group $test_num $tc [string totitle $fn] $cipher]

    # Test constraints
    append line [format "-constraints %s \\\n\t" [string map [list "-" "_"] $cipher]]

    # Test body
    set cmd [format "tls::%s -cipher %s -padding 0 \\\n\t\t" $fn $cipher]

    if {$fn eq "encrypt"} {
	set list1 [list plaintext msg data]
	set list2 [list ciphertext output result]
    } else {
	set list1 [list ciphertext output result]
	set list2 [list plaintext msg data]
    }

    # Add test parameters
    foreach {param names type} [list -key [list key] s -iv [list iv nonce] s -data $list1 s] {
	foreach name $names {
	    if {[info exists config($name)]} {
		set data [get_value $type $config($name)]
		if {$data ne ""} {
		    if {$param ne "-data" || $config(iterations) == 1} {
			append cmd " " $param " " $data " \\\n\t\t"
		    } else {
			set cmd [string cat "set data " $data ";for \{set i 0\} \{\$i < " $config(iterations) "\} \{incr i\} \{set data \[" $cmd " " $param " \$data\]\};set data"]
		    }
		}
		break
	    }
	}
    }
    append line [format {-body {binary encode hex [%s]}} [string trimright $cmd " \\\n\t"]]
    append line " \\\n\t"

    # Test cleanup

    # Test result
    foreach key $list2 {
	if {[info exists config($key)]} {
	    append line [format {-match exact -result %s} [string tolower $config($key)]]
	    break
	}
    }

    # Return codes
    #append line { -returnCodes 0}
    return $line
}

#
# Parse test vector file and get test cases config info
#
proc parse {group filename test_num cipher} {
    set tc 0
    set params [list]

    # Open input file
    if {[catch {open $filename r} ch]} {
	return -code error $ch
    }

    # Open output file
    if {[catch {open [format "%s.test" [file rootname $filename]] w} out]} {
	return -code error $ch
    }

    # Add config info
    puts $out [format "# Auto generated from \"%s\"" [file tail $filename]]
    puts $out [format "lappend auto_path %s" {[file dirname [file dirname [file dirname [file dirname [file join [pwd] [info script]]]]]]}]
    puts $out "package require tls"
    puts $out "package require tcltest\n"
    puts $out "catch {tls::provider legacy}"
    puts $out [format "tcltest::testConstraint %s %s" [string map [list "-" "_"] $cipher] \
	[format {[expr {[lsearch -nocase [tls::ciphers] %s] > -1}]} $cipher]]
    puts $out ""

    # Process file
    while {![eof $ch]} {
	gets $ch line
	set line [string trim $line]
	set len [string length $line]

	if {[string index $line 0] in [list "#" "\["]} {
	    # Skip comments and info lines
	    continue

	} elseif {$len == 0} {
	    if {[llength $params] > 0} {
		# Do test if end of params
		puts $out [do_test $group $cipher $test_num [incr tc] $params encrypt]
		puts $out ""
		puts $out [do_test $group $cipher $test_num [incr tc] $params decrypt]
		puts $out ""
		set params [list]
	    } else {
		# Empty line
	    }

	} else {
	    # Append args to params
	    set index [string first "=" $line]
	    if {$index > -1} {
		set key [string trim [string range $line 0 [expr {$index - 1}]]]
		set value [string trim [string range $line [expr {$index + 1}] end]]
		lappend params [string tolower $key] $value
	    }
	}
    }

    # Handle last test case
    if {[llength $params] > 0} {
	puts $out [do_test $group $cipher $test_num [incr tc] $params encrypt]
	puts $out ""
	puts $out [do_test $group $cipher $test_num [incr tc] $params decrypt]
	puts $out ""
    }
    
    # Cleanup
    puts $out "# Cleanup\n::tcltest::cleanupTests\nreturn"
    close $ch
    close $out
}

#
# Read all config files in directory
#
proc main {path} {
    set test_num 0
    set group [file rootname [file tail $path]]

    foreach filename [glob -directory $path *.txt] {
	puts [format "Processing %s" $filename]
	set tail [file tail $filename]
	if {[string match -nocase "Readme.txt" $tail]} {
	    continue
	}

	set cipher [string trim [file rootname [file tail $filename]]]
	set id [format "%s_%s" $group $cipher]
	set test_num [incr test_ids($id)]
	parse $id $filename $test_num $cipher
    }
}

main [pwd]
exit
