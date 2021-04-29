## Large Configuration Template

bastion   = { memory = "64", processors = "1.5", "count" = 1 }
bootstrap = { memory = "32", processors = "0.5", "count" = 1 }
master    = { memory = "64", processors = "1.5", "count" = 3 }
worker    = { memory = "64", processors = "1.5", "count" = 4 }

