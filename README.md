# Create multisig with single keys and sign


## create multisig and first signature

In the following example we create a multisig 2/3, using 3 public keys and use the first private key to make the partial signed transaction transaction.

```
from multi import *
a=TestnetMultisig(2,3)
a.create_multisig("FIRST-PRIV", ['02ED3F28DA4FF57FE55D97F57E85360A8599093E3C30C37E85A1B9EDF7DC07BE34', '02ECEC779F1EDFAD7F2A37D3EA3FA954FA3DF8FF8F7B42A88F28B035E28E79B0E0', '03638F7C91C2A56A6B2EAC5CF2C545918E447D96973E560CB4E22BAADE136096C4'])
{'public_keys': ['02ED3F28DA4FF57FE55D97F57E85360A8599093E3C30C37E85A1B9EDF7DC07BE34', '02ECEC779F1EDFAD7F2A37D3EA3FA954FA3DF8FF8F7B42A88F28B035E28E79B0E0', '03638F7C91C2A56A6B2EAC5CF2C545918E447D96973E560CB4E22BAADE136096C4'], 'address': '2NB2f37DUMEJTypBziLn6sDJRVKRdCP92oP', 'segwit_address': '2N2tetuNDm3MBqdQ57b6Qb4NMkVjJuuN8aN', 'required_keys': 2, 'total_keys': 3}

a.add_recipient(('tb1qu8l6t60jcv8zhpncyx0h9c2d8cfj3n73qda3cg', 0.0005, 'btc'))
('tb1qu8l6t60jcv8zhpncyx0h9c2d8cfj3n73qda3cg', 0.0005, 'btc')

uno=a.get_transaction()
uno
'01000000000102b8759fda2a05ecf0f1b9f875fc882d1ce0e238fd14f55d19c724b5420697af6f01000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffffa63220a32863c605d13d7e3d05572a8f1e5a233d43a127337783965d85baa93000000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffff0250c3000000000000160014e1ffa5e9f2c30e2b8678219f72e14d3e1328cfd1199001000000000017a91469cd506c6a35cc06a84e4ec8f31175a71da20186870400473044022038bf4546a89f61e04e0313dba5f484195ca5c8f9101b4b4abc6e6c4f8f3ccca102202f93de56d5cdc232afc69b4099a45a038fdf47329ffbe98c8e60726fba1c66df010069522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae040047304402206c7b1e44407c92ad966fa656523420dc8788f838645925f3b6a1b6b12828db240220630fbeb53e682acf09b6011aaacc6eed034cdde70f548db3047c710ca9073e58010069522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae00000000'

a.sign_transaction(uno,"FIRST-PRIV")
'01000000000102b8759fda2a05ecf0f1b9f875fc882d1ce0e238fd14f55d19c724b5420697af6f01000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffffa63220a32863c605d13d7e3d05572a8f1e5a233d43a127337783965d85baa93000000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffff0250c3000000000000160014e1ffa5e9f2c30e2b8678219f72e14d3e1328cfd1199001000000000017a91469cd506c6a35cc06a84e4ec8f31175a71da20186870400483045022100fc13a2514d8efddd683c6932f5978fce6a1163fdfccc629fa108a2c4df3e9d7b022041ce90f83ae0fdcd42b2d94d392876a938b8c69cb24862e339d92325ff345d9101473044022038bf4546a89f61e04e0313dba5f484195ca5c8f9101b4b4abc6e6c4f8f3ccca102202f93de56d5cdc232afc69b4099a45a038fdf47329ffbe98c8e60726fba1c66df0169522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae0400483045022100a0b9c6ecc6faa4ec0790479983298fe676f6894c8053a7dcb222e69af19d75ca02204029b7b01094b7a3560a65fc6d4dba597465f2e161f5bd1dac449d35852c6e680147304402206c7b1e44407c92ad966fa656523420dc8788f838645925f3b6a1b6b12828db240220630fbeb53e682acf09b6011aaacc6eed034cdde70f548db3047c710ca9073e580169522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae00000000'
```

Now we can add the signature from the second private key to an already signed transaction with the first key

```
from multi import *
a=TestnetMultisig(2,3)

a.create_multisig("SECOND-PRIV", ['02ED3F28DA4FF57FE55D97F57E85360A8599093E3C30C37E85A1B9EDF7DC07BE34', '02ECEC779F1EDFAD7F2A37D3EA3FA954FA3DF8FF8F7B42A88F28B035E28E79B0E0', '03638F7C91C2A56A6B2EAC5CF2C545918E447D96973E560CB4E22BAADE136096C4'])
{'public_keys': ['02ED3F28DA4FF57FE55D97F57E85360A8599093E3C30C37E85A1B9EDF7DC07BE34', '02ECEC779F1EDFAD7F2A37D3EA3FA954FA3DF8FF8F7B42A88F28B035E28E79B0E0', '03638F7C91C2A56A6B2EAC5CF2C545918E447D96973E560CB4E22BAADE136096C4'], 'address': '2NB2f37DUMEJTypBziLn6sDJRVKRdCP92oP', 'segwit_address': '2N2tetuNDm3MBqdQ57b6Qb4NMkVjJuuN8aN', 'required_keys': 2, 'total_keys': 3}

a.sign_transaction(uno,"SECOND-PRIV")
'01000000000102b8759fda2a05ecf0f1b9f875fc882d1ce0e238fd14f55d19c724b5420697af6f01000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffffa63220a32863c605d13d7e3d05572a8f1e5a233d43a127337783965d85baa93000000000232200202cec399422528959e7f9e4f6034ad70127989573c25da764b96f64f2db196d23ffffffff0250c3000000000000160014e1ffa5e9f2c30e2b8678219f72e14d3e1328cfd1199001000000000017a91469cd506c6a35cc06a84e4ec8f31175a71da20186870400483045022100fc13a2514d8efddd683c6932f5978fce6a1163fdfccc629fa108a2c4df3e9d7b022041ce90f83ae0fdcd42b2d94d392876a938b8c69cb24862e339d92325ff345d9101473044022038bf4546a89f61e04e0313dba5f484195ca5c8f9101b4b4abc6e6c4f8f3ccca102202f93de56d5cdc232afc69b4099a45a038fdf47329ffbe98c8e60726fba1c66df0169522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae0400483045022100a0b9c6ecc6faa4ec0790479983298fe676f6894c8053a7dcb222e69af19d75ca02204029b7b01094b7a3560a65fc6d4dba597465f2e161f5bd1dac449d35852c6e680147304402206c7b1e44407c92ad966fa656523420dc8788f838645925f3b6a1b6b12828db240220630fbeb53e682acf09b6011aaacc6eed034cdde70f548db3047c710ca9073e580169522102ecec779f1edfad7f2a37d3ea3fa954fa3df8ff8f7b42a88f28b035e28e79b0e02102ed3f28da4ff57fe55d97f57e85360a8599093e3c30c37e85a1b9edf7dc07be342103638f7c91c2a56a6b2eac5cf2c545918e447d96973e560cb4e22baade136096c453ae00000000'
```