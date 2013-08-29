;; This policy is satisfied if the remote party is a "Service" sponsored
;; by Acme Springfield.  Charlie  uses this policy to protect his 
;; access exception for "Project X" and his sensitive document training
;; credential
;;
(defrule rule-springfield-service
  (credential (id ?i1) (issuer "O=Acme Fabrication,C=USA")
                       (subject "O=Acme Fabrication,C=USA"))

  (credential (id ?i2) (map ?m2)
                       (issuer "O=Acme Fabrication,C=USA")
                       (subject "O=Acme Springfield,C=USA"))
  (test (eq "Branch Office" (?m2 get "Type")))
 
  (credential (id ?i3) (map ?m3)
              (subject ?s3) (issuer "O=Acme Springfield,C=USA"))
  (test (eq "Service" (?m3 get "Type")))

  (credential-chain (credentials $?c))
  (test (is-root ?i1 ?c))
  (test (is-nth ?i2 2 ?c))
  (test (is-leaf ?i3 ?c))
=>
  (assert (satisfaction (resource-name creds) (credentials ?c))))