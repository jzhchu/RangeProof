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
	test()
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
	h1 := GenerateH1(verifier.HVector,2,10)
	yn := GenerateY(2,10)

	commith1 := CommitSingleVector(h1,yn)
	commith := CommitSingleVector(verifier.HVector,GenerateY(1,10))

	fmt.Println(IsEqual(commith1,commith))

	commitZ := CommitSingle(verifier.H, big.NewInt(int64(verifier.z)).Bytes())
	commitZ1 := CommitSingle(verifier.H, negByte(verifier.z).Bytes())
	fmt.Println("z",verifier.z)
	fmt.Println("-z",negByte(verifier.z))
	fmt.Println(addInP(big.NewInt(int64(verifier.z)),negByte(verifier.z)))
	fmt.Println(MultiCommit(commitZ,commitZ1).x)
	fmt.Println(prover.lx)
	fmt.Println(prover.rx)

	P := big.NewInt(0)
	P.Sub(curve.P,big.NewInt(2))
	fmt.Println(curve.P)
	fmt.Println(addInP(P,big.NewInt(1)))

}
