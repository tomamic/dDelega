;; Allow access to FTEs in 246x if have sensitive docs training
;;
(defrule fte-docs-246x
  (employeeId (empType "FTE") (org ?org) (chain $?c1))
  (test (and (<= 2460 ?org) (> 2470 ?org)))
  (sensitive-docs (chain $?c2))
=>
  (assert (satisfaction (resource-name project_x) 
                        (credentials (dup-elim ?c1 ?c2)))))

;; Allow access if FTE of 24xx, has sensitive docs training, and 
;; has an access exception issued by Alice or Bob
;;
(defrule fte-docs-24xx-exn
  (employeeId (empType "FTE") (org ?org) (chain $?c1))
  (test (and (<= 2400 ?org) (> 2500 ?org)))
  (sensitive-docs (chain $?c2))
  (accessException (project "Project X") (issuer ?iss) (chain $?c3))
  (or (test (eq "CN=Bob,O=Acme Springfield,C=USA" ?iss))
      (test (eq "CN=Alice,O=Acme Springfield,C=USA" ?iss)))
=>
  (assert (satisfaction (resource-name project_x) 
                        (credentials (dup-elim ?c1 ?c2 ?c3)))))