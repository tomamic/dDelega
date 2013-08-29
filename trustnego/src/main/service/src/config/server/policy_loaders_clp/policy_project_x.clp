;; Allow access to FTEs in 246x if have sensitive docs training
;;
(defrule fte-docs-246x
  (employeeId (empType "FTE") (org ?org) (chain $?c1))
  (test (and (<= 2460 ?org) (> 2470 ?org)))
=>
  (assert (satisfaction (resource-name project_x) 
                        (credentials ?c1))))

