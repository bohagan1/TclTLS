#
# Create Test Files for Test Vectors
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
    array set config [list key "" repeat 1 length "" offset 0 end end plaintext {""} ciphertext {""}]
    array set config $params
    set end [expr {$config(offset) + [string length $config(plaintext)]/2 - 1}]

    # Test info
    set line [format "\ntcltest::test %s_%s-%d.%d {%s %s offset %d}" [string map [list "-" "_"] \
	$group] [string map [list "-" "_"] $cipher] $test_num $tc [string totitle $fn] $cipher $config(offset)]

    # Test constraints
    append line [format " \\\n\t-constraints %s" [string map [list "-" "_"] $cipher]]

    # Test body
    if {$fn eq "encrypt"} {
	set cmd [format "tls::encrypt -cipher %s -padding 0 -key %s \\\n\t\t-data %s" $cipher \
	    [get_value s $config(key)] [get_value s $config(plaintext) $config(repeat)]]
  
	append line " \\\n\t" [format {-body {binary encode hex [string range [%s] %d %d]}} $cmd $config(offset) $end] " \\\n\t"
    } else {
	set ecmd [format "tls::encrypt -cipher %s -padding 0 -key %s \\\n\t\t-data %s" $cipher \
	    [get_value s $config(key)] [get_value s $config(plaintext) $config(repeat)]]
	set cmd [format "tls::decrypt -cipher %s -padding 0 -key %s \\\n\t\t-data \[%s\]" $cipher \
	    [get_value s $config(key)] $ecmd]
	append line " \\\n\t" [format {-body {binary encode hex [string range [%s] %d %d]}} $cmd $config(offset) $end] " \\\n\t"
    }

    # Test result
    if {$fn eq "encrypt"} {
	append line [format {-match exact -result %s} $config(ciphertext)]
    } else {
	append line [format {-match exact -result %s} $config(plaintext)]
    }
    return $line
}

#
# Parse test vector file and create test files with test cases
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
		puts $out [do_test $group $cipher $test_num [incr tc] $params "encrypt"]
		puts $out ""
		puts $out [do_test $group $cipher $test_num [incr tc] $params "decrypt"]
		puts $out ""
		set params [list]
	    } else {
		# Empty line
	    }

	} else {
	    # Append args to params
	    set index [string first "=" $line]
	    if {$index > -1} {
		set key [string trim [string range $line 0 [incr index -1]]]
		set value [string trim [string range $line [incr index 2] end]]
		lappend params [string tolower $key] $value
	    }
	}
    }

    # Handle last test case
    if {[llength $params] > 0} {
	puts $out [do_test $group $cipher $test_num [incr tc] $params "encrypt"]
	puts $out ""
	puts $out [do_test $group $cipher $test_num [incr tc] $params "decrypt"]
	puts $out ""
    }
    
    # Cleanup
    puts $out "# Cleanup\n::tcltest::cleanupTests\nreturn"
    close $ch
    close $out
}

#
# Read all test vector files in directory
#
proc main {path} {
    set group [file rootname [file tail $path]]

    foreach filename [glob -directory $path *.txt] {
	puts [format "Processing %s" $filename]
	set tail [file tail $filename]
	if {[string match -nocase "Readme.txt" $tail]} {
	    continue
	}

	set cipher [file rootname [file tail $filename]]
	set id [format "%s_%s" $group $cipher]
	set test_num [incr test_ids($id)]
	if {$cipher eq "rc4-128"} {set cipher "rc4"}
	parse $group $filename $test_num $cipher
    }
}

main [pwd]
exit
