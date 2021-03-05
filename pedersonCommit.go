package main

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v3"
	"math/big"
)

var curve *secp256k1.KoblitzCurve


type Point struct {
	x *big.Int
	y *big.Int
}

//生成椭圆曲线上的点
func GeneratePoint() Point {
	private, _ := secp256k1.GeneratePrivateKey()
	pub := private.PubKey()
	var point Point
	point.x = pub.X()
	point.y = pub.Y()

	return point
}

//根据G和H，计算pederson承诺，返回椭圆曲线上的点
//P = v*G + r*H
func Commit(G Point, H Point, secret []byte, blinding []byte) Point {
	var commit Point
	vx, vy := curve.ScalarMult(G.x, G.y, secret)
	rx, ry := curve.ScalarMult(H.x, H.y, blinding)
	commit.x, commit.y = curve.Add(vx, vy, rx, ry)

	return commit
}

//为一个数值提供承诺
func CommitSingle(H Point, secret []byte) Point {
	var commit Point
	commit.x, commit.y = curve.ScalarMult(H.x, H.y, secret)
	return commit
}


//生成N个椭圆曲线上的点，用于为向量提供承诺
func GenerateMultiPoint(n int64) []Point {
	var points []Point
	for i := n; i > 0; i-- {
		points = append(points, GeneratePoint())
	}
	return points
}

//为矢量提供承诺
//todo len
func CommitVectors(G_vector []Point, H_vector []Point, Secret1 []*big.Int, Secret2 []*big.Int) Point {
	var commit Point

	commit = Commit(G_vector[0], H_vector[0], Secret1[0].Bytes(), Secret2[0].Bytes())
	for i := 1; i < len(G_vector); i++ {
		commitArray := Commit(G_vector[i], H_vector[i], Secret1[i].Bytes(), Secret2[i].Bytes())
		commit.x, commit.y = curve.Add(commit.x, commit.y, commitArray.x, commitArray.y)
	}
	return commit
}

//为一个矢量提供承诺
func CommitSingleVector(H_vector []Point, secret []*big.Int) Point {
	var commit Point

	commit = CommitSingle(H_vector[0], secret[0].Bytes())
	for i := 1; i < len(H_vector); i++ {
		commitArray := CommitSingle(H_vector[i], secret[i].Bytes())
		commit.x, commit.y = curve.Add(commit.x, commit.y, commitArray.x, commitArray.y)
	}
	return commit
}

//验证两个承诺是否相等
func IsEqual(commit0 Point, commit1 Point) bool {
	if commit0.x.Cmp(commit1.x) == 0 && commit0.y.Cmp(commit1.y) == 0 {
		return true
	}
	return false
}

//两个承诺相乘（在椭圆曲线中，是两个点相加）
func MultiCommit(commit0 Point, commit1 Point) (commit Point) {
	commit.x, commit.y = curve.Add(commit0.x, commit0.y, commit1.x, commit1.y)
	return commit
}

//将超出域的数映射在Zp中
func PutInP(num *big.Int, curve *secp256k1.KoblitzCurve) *big.Int {
	//sub := big.NewInt(1)
	temp := big.NewInt(0)
	return num.Mod(num, temp.Sub(curve.P, big.NewInt(1)))
	//return num.Mod(num,curve.P)
}

//判断一个数是否在Zp中,如果大于p-1，返回1；小于0，返回-1；在Zp中，返回0
func isInP(num *big.Int, curve *secp256k1.KoblitzCurve) int {
	if num.Cmp(curve.P) >= 0 {
		return 1
	}
	if num.Cmp(big.NewInt(0)) < 0 {
		return -1
	}
	return 0
}

func addInP(a *big.Int, b *big.Int) *big.Int {
	var m,n secp256k1.ModNScalar
	c := big.NewInt(0)

	m.SetByteSlice(a.Bytes())
	n.SetByteSlice(b.Bytes())

	m.Add(&n)
	mbyte := m.Bytes()
	c.SetBytes(mbyte[0:32])
	return c
}

//对*big.Int类型的数字求逆元
func inverseBig(a *big.Int) *big.Int {
	var m secp256k1.ModNScalar
	b := big.NewInt(0)
	m.SetByteSlice(a.Bytes())
	m.InverseNonConst()
	mbyte := m.Bytes()
	b.SetBytes(mbyte[0:32])
	return b
}

//对byte类型的数取反
func negByte(a byte) *big.Int {
	var m secp256k1.ModNScalar
	b := big.NewInt(0)
	m.SetInt(uint32(a))
	m.Negate()
	mbyte := m.Bytes()
	b.SetBytes(mbyte[0:32])
	return b
}

func new() {
	var m secp256k1.ModNScalar
	m.SetInt(4)
	a := m.Bytes()
	a1 := a[0:32]
	a2 := big.NewInt(0)
	a2.SetBytes(a1)
	fmt.Println(a1)
	fmt.Println(a2.Bytes())
	m.InverseNonConst()
	commit0 := CommitSingle(prover.H, big.NewInt(4).Bytes())
	b := m.Bytes()
	fmt.Println(big.NewInt(2).Bytes())
	fmt.Println(b)
	b1 := b[0:32]
	b2 := big.NewInt(0)
	b2.SetBytes(b1)
	fmt.Println(b2.Bytes())
	commit1 := CommitSingle(commit0, b2.Bytes())
	fmt.Println(commit1.x)
	fmt.Println(prover.H.x)
}
