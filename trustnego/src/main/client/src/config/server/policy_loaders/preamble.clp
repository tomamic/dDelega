;;
;; See if they've had sensitive documents training
;;
(deftemplate sensitive-docs
  (slot subject)
  (multislot chain))

(defrule rule-has-sensitive-docs
  (credential (id ?i1) (issuer "O=Acme Fabrication,C=USA") 
              (subject "O=Acme Fabrication,C=USA"))
                       
  (credential (id ?i2) (issuer "O=Acme Fabrication,C=USA")
              (subject ?s2) (map ?m2))
  (test (eq "Sensitive Document Training" (?m2 get "Type")))  

  (credential-chain (credentials $?c))
  (test (is-root ?i1 ?c))
  (test (is-leaf ?i2 ?c))
=>
  (assert (sensitive-docs (subject ?s2) (chain ?c))))


;;
;; Extract information about employees
;;
(deftemplate employeeId
  (slot subject)
  (slot empType)
  (slot org)
  (multislot chain))

(defrule rule-is-employee
  (credential (id ?i1) (issuer "O=Acme Fabrication,C=USA")
              (subject "O=Acme Fabrication,C=USA"))

  (credential (id ?i2) (map ?m2)
              (issuer "O=Acme Fabrication,C=USA")
              (subject "O=Acme Springfield,C=USA"))
  (test (eq "Branch Office" (?m2 get "Type")))
 
  (credential (id ?i3) (map ?m3) (subject ?s3)
              (issuer "O=Acme Springfield,C=USA"))
  (test (eq "Employee" (?m3 get "Type")))

  (credential-chain (credentials $?c))
  (test (is-leaf ?i3 ?c))
  (test (is-root ?i1 ?c))
  (test (is-nth ?i2 2 ?c))
=>
  (assert (employeeId (subject ?s3) 
                      (empType (?m3 get "EmpType"))
                      (org (?m3 get "Org"))
                      (chain ?c))))


;;
;; Get information about exceptions
;;
(deftemplate accessException
  (slot subject)
  (slot issuer)
  (slot project)
  (multislot chain))

(defrule rule-has-exception
  ;; Exceptions come from a chain Acme->Acme Springfield->
  ;; Employee->Exception holder
  (credential (id ?i1) (issuer "O=Acme Fabrication,C=USA")
              (subject "O=Acme Fabrication,C=USA"))

  (credential (id ?i2) (map ?m2)
              (issuer "O=Acme Fabrication,C=USA")
              (subject "O=Acme Springfield,C=USA"))
  (test (eq "Branch Office" (?m2 get "Type")))
 
  ;; This is the exception-issuer's credential
  (credential (id ?i3) (map ?m3) (issuer "O=Acme Springfield,C=USA"))
  (test (eq "Employee" (?m3 get "Type")))
  
  ;; This is the exception itself  
  (credential (id ?i4) (subject ?s4) (issuer ?iss4) (map ?m4))
  (test (eq "Exception" (?m4 get "Type")))
  
  ;; check constraints on chain
  (credential-chain (credentials $?c))
  (test (is-root ?i1 ?c))
  (test (is-nth ?i2 2 ?c))
  (test (is-nth ?i3 3 ?c))
  (test (is-leaf ?i4 ?c))
=>
  (assert (accessException (subject ?s4)
                           (issuer ?iss4)
                           (project (?m4 get "Project"))
                           (chain ?c))))

