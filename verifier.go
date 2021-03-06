package main

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"math/big"
)

type Verifier struct {
	//公开的参数，包括G,H和G,H的矢量，要承诺的范围n,以及相同的椭圆曲线
	G, H             Point
	GVector, HVector []Point
	n                int64
	curve            *secp256k1.KoblitzCurve

	//prover发送的承诺A,S
	A, S Point

	//发给prover的随机数y,z
	y, z byte

	//prover发送的承诺T1,T2
	T1, T2 Point

	//发送给prover的随机数x
	x int

	//承诺P
	P Point

	//和矢量h相关的h`
	h1 []Point

	//零知识证明阶段Prover发送的相关的变量
	proverZKP ProverZKP
}

func (verifier *Verifier) New(G Point, H Point, GVector []Point, HVector []Point, n int64, curve secp256k1.KoblitzCurve) {
	verifier.G = G
	verifier.H = H
	verifier.GVector = GVector
	verifier.HVector = HVector
	verifier.n = n
	verifier.curve = &curve
	//verifier.y = 0
	verifier.y = GenerateRandom()

}

func (verifier *Verifier) GetAS(A Point, S Point) {
	verifier.A = A
	verifier.S = S
}

func (verifier *Verifier) GenerateYZ() {
	verifier.z = GenerateRandom()
	//verifier.z = 0
}

func (verifier *Verifier) GetT(T1 Point, T2 Point) {
	verifier.T1 = T1
	verifier.T2 = T2
}

func (verifier *Verifier) GenerateX() {
	verifier.x = GenerateRandomInt()
	//verifier.x = 10000000000
}

func (verifier *Verifier) VerifyZKP() bool {
	if !verifier.verifyTx() {
		fmt.Println("验证t(x)失败")
		return false
	}
	if !verifier.verifyP() {
		fmt.Println("验证承诺P失败")
		return false
	}
	if !verifier.verifyEqual() {
		fmt.Println("验证等式相等失败")
		return false
	}
	return true
}

//验证t(x)
func (verifier *Verifier) verifyTx() bool {
	x2 := big.NewInt(1)
	z2 := big.NewInt(1)
	x2.Mul(big.NewInt(int64(verifier.x)), big.NewInt(int64(verifier.x)))
	z2.Mul(big.NewInt(int64(verifier.z)), big.NewInt(int64(verifier.z)))

	commit0 := Commit(verifier.G, verifier.H, verifier.proverZKP.tx.Bytes(), verifier.proverZKP.taux.Bytes())
	commitVg := Commit(verifier.proverZKP.V, verifier.G, z2.Bytes(), verifier.calculateDelta().Bytes())
	commitT := Commit(verifier.T1, verifier.T2, big.NewInt(int64(verifier.x)).Bytes(), x2.Bytes())
	return IsEqual(commit0, MultiCommit(commitVg, commitT))
}

//根据y,z，计算δ(x,y)
func (verifier *Verifier) calculateDelta() *big.Int {
	delta := big.NewInt(1)
	y2n := GenerateY(2, verifier.n)
	z2 := big.NewInt(1)
	z3 := big.NewInt(1)
	yn := GenerateY(verifier.y, verifier.n)

	z2 = mulInP(big.NewInt(int64(verifier.z)), big.NewInt(int64(verifier.z)))
	z3 = mulInP(z2,big.NewInt(int64(verifier.z)))
	z2 = addInP(big.NewInt(int64(verifier.z)),negBig(z2))

	y1n := Inner_Proof(GenerateZ(1, verifier.n), yn)

	z2 = mulInP(z2, y1n)
	y2nInner := Inner_Proof(GenerateZ(1, verifier.n), y2n)
	z3 = mulInP(z3,y2nInner)
	delta = addInP(z2,negBig(z3))
	//fmt.Println("delta",negBig(delta))
	return delta
}

//生成承诺P
func (verifier *Verifier) generateP() {
	//neg := big.NewInt(0)

	A := verifier.A
	S := verifier.S
	yn := GenerateY(verifier.y,verifier.n)
	y2n := GenerateY(2,verifier.n)
	vector := CalVectorAdd(CalVectorTimes(yn, int64(verifier.z)),CalVectorTimes(y2n,int64(verifier.z)*int64(verifier.z)))
	h1 := GenerateH1(verifier.HVector,verifier.y,verifier.n)
	verifier.h1 = h1

	commitAS := Commit(A,S,big.NewInt(1).Bytes(),big.NewInt(int64(verifier.x)).Bytes())
	//commitZ := CommitSingle(verifier.G, negByte(verifier.z).Bytes())
	//todo
	commitZ := CommitSingleVector(verifier.GVector,GeneratenegZVector(verifier.z,verifier.n))
	commitPoly := CommitSingleVector(h1, vector)

	verifier.P = MultiCommit(commitAS,MultiCommit(commitZ, commitPoly))
}

//验证承诺P
func (verifier *Verifier) verifyP() bool {
	verifier.generateP()
	commitLR := CommitVectors(verifier.GVector,verifier.h1,verifier.proverZKP.lx,verifier.proverZKP.rx)
	commitMju := CommitSingle(verifier.H,verifier.proverZKP.mju.Bytes())
	P1 := MultiCommit(commitLR,commitMju)
	return IsEqual(verifier.P, P1)
}

//验证lx和rx是否相等
func (verifier *Verifier) verifyEqual() bool {
	lx := verifier.proverZKP.lx
	rx := verifier.proverZKP.rx
	tx := Inner_ProofBig(lx, rx)
	return tx.Cmp(verifier.proverZKP.tx) == 0
}
