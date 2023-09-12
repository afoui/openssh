#	$OpenBSD: keygen-sshfp.sh,v 1.2 2021/07/19 02:29:28 dtucker Exp $
#	Placed in the Public Domain.

tid="keygen-sshfp"

trace "keygen fingerprints"
fp=`${SSHKEYGEN} -r test -f ${SRC}/ed25519_openssh.pub | \
    awk '$5=="1"{print $6}'`
if [ "$fp" != "8a8647a7567e202ce317e62606c799c53d4c121f" ]; then
	fail "keygen fingerprint sha1"
fi
fp=`${SSHKEYGEN} -r test -f ${SRC}/ed25519_openssh.pub | \
    awk '$5=="2"{print $6}'`
if [ "$fp" != \
    "54a506fb849aafb9f229cf78a94436c281efcb4ae67c8a430e8c06afcb5ee18f" ]; then
	fail "keygen fingerprint sha256"
fi

if ${SSH} -Q key-plain | grep ssh-rsa >/dev/null; then
	fp=`${SSHKEYGEN} -r test -f ${SRC}/rsa_openssh.pub | awk '$5=="1"{print $6}'`
	if [ "$fp" != "c1856031cbdd5e026abf958a5a0e51dcc1fee00b" ]; then
		fail "keygen fingerprint sha1"
	fi
	fp=`${SSHKEYGEN} -r test -f ${SRC}/rsa_openssh.pub | awk '$5=="2"{print $6}'`
	if [ "$fp" != \
	    "ff0edf55f1ba959b3eef3f06d5aed04d1e9f172d0b9ccf21c12ab9b3e6379157" ]; then
		fail "keygen fingerprint sha256"
	fi
fi
