
# Common Constraints
package require tls

# Supported protocols
set protocols [list ssl2 ssl3 tls1 tls1.1 tls1.2 tls1.3]
foreach protocol $protocols {
    ::tcltest::testConstraint $protocol 0
    ::tcltest::testConstraint !$protocol 1
}

foreach protocol [::tls::protocols] {
    ::tcltest::testConstraint $protocol 1
    ::tcltest::testConstraint !$protocol 0
}

# OpenSSL version
::tcltest::testConstraint OpenSSL [string match "OpenSSL*" [::tls::version]]

# Legacy OpenSSL v1.1.1 vs new v3.x
scan [lindex [split [::tls::version]] 1] %f version
::tcltest::testConstraint new_api [expr {$version >= 3.0}]
