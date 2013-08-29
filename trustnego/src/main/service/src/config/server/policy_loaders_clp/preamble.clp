;;
;; Extract information about employees
;;
(deftemplate employeeId
  (slot subject)
  (slot empType)
  (slot org)
  (multislot chain))
  
(defquery get-employees (employeeId))

(defrule rule-is-employee
  (credential (id ?i1) (issuer "CN=Acme Fabrication,O=Acme Fabrication,ST=Some-State,C=US")
              (subject "CN=Acme Fabrication,O=Acme Fabrication,ST=Some-State,C=US"))

  (credential (id ?i2) (map ?m2)
              (issuer "CN=Acme Fabrication,O=Acme Fabrication,ST=Some-State,C=US")
              (subject "CN=Acme Springfield,O=Acme Springfield,ST=Some-State,C=US"))
 
  (credential (id ?i3) (map ?m3) (subject ?s3)
              (issuer "CN=Acme Springfield,O=Acme Springfield,ST=Some-State,C=US"))
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