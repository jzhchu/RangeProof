package main

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"math/big"
)

var prover Prover
var verifier Verifier

func main(){

	setup(100,10)
	zkpConstruct()
	zkp()
	isInRange := zkpVerify()
	fmt.Println(isInRange)
	//test()
}

func setup(v int64,n int64) {

	curve = secp256k1.S256()
	g := GeneratePoint()
	h := GeneratePoint()
	gVector := GenerateMultiPoint(n)
	hVector := GenerateMultiPoint(n)

	//创建一个prover对象
	err := prover.New(g,h,gVector,hVector,v,n,*curve)
	if err!=nil {
		fmt.Println(err)
		return
	}
	//创建一个verifier对象
	verifier.New(g,h,gVector,hVector,n,*curve)

	//获取A,S，将两个承诺传递给verifier
	A,S := prover.GetAS()
	verifier.GetAS(A,S)

	//在verifier接收到A,S后，将y,z传递给prover
	verifier.GenerateYZ()
	prover.y = verifier.y
	prover.z = verifier.z

}

func zkpConstruct(){

	//获取T1,T2，将两个承诺传递给verifier
	T1,T2 := prover.GetT()
	verifier.GetT(T1,T2)

	//将随机数x传递给prover
	verifier.GenerateX()
	prover.x = verifier.x

}

func zkp(){
	proverZKP := prover.GetProverZKP()
	verifier.proverZKP = proverZKP
}

func zkpVerify() bool{
	return verifier.VerifyZKP()
}

func test() {
	tx := negBig(big.NewInt(11))
	taux := big.NewInt(0)
	delta := negBig(big.NewInt(31))
	x0 := negBig(big.NewInt(11))
	x1 := big.NewInt(20)
	x2 := negBig(big.NewInt(31))

	commit2 := CommitSingle(prover.H,x0.Bytes())
	commit3 := Commit(prover.H,prover.H,x1.Bytes(),x2.Bytes())


	V := Commit(prover.G,prover.H,big.NewInt(prover.v).Bytes(),big.NewInt(int64(prover.gamma)).Bytes())
	commit0 := Commit(prover.G,prover.H,tx.Bytes(),taux.Bytes())
	commit1:= Commit(V,prover.G,big.NewInt(1).Bytes(),delta.Bytes())

	fmt.Println(IsEqual(commit0,commit1))
	fmt.Println(IsEqual(commit2,commit3))

}
