package main

import (
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"math/big"
)

type Prover struct {
	//公开的参数，包括G,H和G,H的矢量,需要证明的范围n，以及相同的椭圆曲线
	G, H             Point
	GVector, HVector []Point
	n                int64
	curve            *secp256k1.KoblitzCurve

	//v是需要进行范围证明的值，V是对v的承诺
	v int64
	V Point

	//和A,S承诺相关的参数
	aL    []*big.Int
	aR    []*big.Int
	sL    []*big.Int
	sR    []*big.Int
	A, S  Point
	alpha byte
	rho   byte

	//和T1,T2承诺相关的参数
	y, z   byte
	tau1   byte
	tau2   byte
	t1, t2 *big.Int
	T1, T2 Point

	//零知识证明阶段的相关参数
	x      int
	gamma  byte
	lx, rx []*big.Int
	tx     *big.Int
	taux   *big.Int
	mju    *big.Int
}

type ProverZKP struct {
	taux   *big.Int
	mju    *big.Int
	lx, rx []*big.Int
	tx     *big.Int
	V      Point
}

func (prover *Prover) New(G Point, H Point, GVector []Point, HVector []Point, v int64, n int64,curve secp256k1.KoblitzCurve) error {
	if int64(len(GVector)) < n || int64(len(HVector)) < n {
		return errors.New("G,H矢量的长度不足n位，无法提供证明")
	}
	prover.G = G
	prover.H = H
	prover.GVector = GVector[:n]
	prover.HVector = HVector[:n]
	prover.v = v
	prover.n = n
	prover.curve = &curve

	return nil
}

//用于获取承诺A和承诺S
func (prover *Prover) GetAS() (Point, Point) {
	prover.generateAS()
	return prover.A, prover.S
}

//生成aL,aR,sL,sR以及A承诺,S承诺
func (prover *Prover) generateAS() {
	err := errors.New("")

	//生成aL,aR两个矢量
	prover.aL, err = GenerateA_L(big.NewInt(prover.v), prover.n)
	if err != nil {
		fmt.Println(err)
		return
	}
	prover.sL = GenerateS(prover.n) //在此生成sL是因为以当前的系统时间为种子，生成的随机数，如果sL和sR生成的间隔很近，会导致两个矢量重复。
	prover.aR = GenerateA_R(prover.aL)

	//生成承诺A
	prover.alpha = GenerateRandom()
	commitA := CommitVectors(prover.GVector, prover.HVector, prover.aL, prover.aR)
	commitAlpha := CommitSingle(prover.H, []byte{prover.alpha})
	prover.A.x, prover.A.y = curve.Add(commitA.x, commitA.y, commitAlpha.x, commitAlpha.y)

	//生成承诺S
	prover.rho = GenerateRandom()
	prover.sR = GenerateS(prover.n)
	commitS := CommitVectors(prover.GVector, prover.HVector, prover.sL, prover.sR)
	commitRho := CommitSingle(prover.H, []byte{prover.rho})
	prover.S.x, prover.S.y = curve.Add(commitS.x, commitS.y, commitRho.x, commitRho.y)
}

//计算t(x)中的t1,t2两个系数
func (prover *Prover) calculateT() {
	yn := GenerateY(prover.y, prover.n)
	srYn := CalHadamardVectorBig(prover.sR, yn)

	//计算t2
	prover.t2 = PutInP(Inner_ProofBig(prover.sL, srYn),prover.curve)

	//生成tau2
	prover.tau2 = GenerateRandom()

	//计算t1
	sum := big.NewInt(0)
	//t1的第一项
	t11 := big.NewInt(0)
	y2n := GenerateY(2, prover.n)
	sl2n := Inner_ProofBig(prover.sL, y2n)
	t11.Mul(big.NewInt(int64(prover.z)*int64(prover.z)),sl2n)
	//t1的第二项
	t12 := Inner_ProofBig(prover.sL,CalHadamardVectorBig(yn,prover.aR))
	//t1的第三项
	t13 := Inner_ProofBig(CalVectorTimes(prover.sL,int64(prover.z),prover.curve),yn)
	//t1的第四项
	t14 := Inner_ProofBig(CalVectorSubByte(prover.aL,GenerateZ(prover.z,prover.n),prover.curve),CalHadamardVectorBig(yn,prover.sR))
	sum.Add(t11,t12)
	sum.Add(sum,t13)
	sum.Add(sum,t14)
	prover.t1 = PutInP(sum,prover.curve)

	//生成tau1
	prover.tau1 = GenerateRandom()
}

//用于获取承诺T1,T2
func (prover *Prover) GetT() (Point, Point) {
	prover.generateT()
	return prover.T1, prover.T2
}

//生成T1,T2两个承诺
func (prover *Prover) generateT() {
	prover.calculateT()
	prover.T2 = Commit(prover.G, prover.H, prover.t2.Bytes(), big.NewInt(int64(prover.tau2)).Bytes())
	prover.T1 = Commit(prover.G, prover.H, prover.t1.Bytes(), big.NewInt(int64(prover.tau1)).Bytes())
}

//计算l(x)
func (prover *Prover) calculateLx() {
	var lx []*big.Int
	lx = CalVectorAdd(CalVectorSubByte(prover.aL,GenerateZ(prover.z,prover.n),prover.curve),CalVectorTimes(prover.sL,int64(prover.x),prover.curve),prover.curve)
	prover.lx = lx
}

//计算r(x)
func (prover *Prover) calculateRx() {
	var rx []*big.Int
	yn := GenerateY(prover.y, prover.n)
	y2n := GenerateY(2, prover.n)

	rx = CalVectorAdd(CalHadamardVectorBig(yn,CalVectorAdd(prover.aR,CalVectorAddByte(CalVectorTimes(prover.sR,int64(prover.x),prover.curve),GenerateZ(prover.z,prover.n),prover.curve),prover.curve)),CalVectorTimes(y2n,int64(prover.z)*int64(prover.z),prover.curve),prover.curve)
	prover.rx = rx
}

//计算t(x)的值，即<l(x),r(x)>
func (prover *Prover) calculateTx() {
	prover.tx = PutInP(Inner_ProofBig(prover.lx, prover.rx),prover.curve)

}

//计算taux的值
func (prover *Prover) calculateTaux() {
	x2 := big.NewInt(1)
	xtau2 := big.NewInt(1)
	xtau1 := big.NewInt(1)
	z := big.NewInt(1)
	taux := big.NewInt(0)

	x2.Mul(big.NewInt(int64(prover.x)), big.NewInt(int64(prover.x)))
	xtau2.Mul(big.NewInt(int64(prover.tau2)), x2)
	xtau1.Mul(big.NewInt(int64(prover.tau1)), big.NewInt(int64(prover.x)))

	prover.gamma = GenerateRandom()
	z.Mul(big.NewInt(int64(prover.z)), big.NewInt(int64(prover.z)))
	z.Mul(z, big.NewInt(int64(prover.gamma)))

	taux.Add(xtau2, xtau1)
	taux.Add(taux, z)
	prover.taux = PutInP(taux,prover.curve)
}

//计算mju值
func (prover *Prover) calculateMju() {
	prover.mju = PutInP(big.NewInt(int64(prover.alpha) + int64(prover.rho)*int64(prover.x)),prover.curve)
}

//生成关于V的承诺
func (prover *Prover) generateV() {
	v := big.NewInt(prover.v)
	prover.V = Commit(prover.G, prover.H, v.Bytes(), big.NewInt(int64(prover.gamma)).Bytes())
}

func (prover *Prover) GetProverZKP() ProverZKP {
	prover.calculateMju()
	prover.calculateTaux()
	prover.calculateLx()
	prover.calculateRx()
	prover.calculateTx()
	prover.generateV()

	proverZKP := ProverZKP{
		taux: prover.taux,
		mju:  prover.mju,
		tx:   prover.tx,
		lx:   prover.lx,
		rx:   prover.rx,
		V:    prover.V,
	}
	return proverZKP
}
