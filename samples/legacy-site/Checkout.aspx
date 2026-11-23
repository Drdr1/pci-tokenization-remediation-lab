<%@ Page Language="C#" CodeBehind="Checkout.aspx.cs" %>
<form runat="server">
  <asp:TextBox ID="txtCardNumber" runat="server" MaxLength="19" />
  <asp:TextBox ID="txtExpiry" runat="server" />
  <asp:TextBox ID="txtCVV" runat="server" MaxLength="4" />
  <asp:Button ID="btnPay" runat="server" Text="Pay" OnClick="btnPay_Click" />
</form>
